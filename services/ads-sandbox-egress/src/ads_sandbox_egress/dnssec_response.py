"""Client signaling for a separately checked synthetic DNS candidate.

Not a raw upstream forwarding path. The view owner must acquire/inspect data,
check a candidate's expected authentication outcome and durably publish its
dependencies before calling ``render``. Policy/budget errors propagate as
RequestDenied before this layer; they are never converted to SERVFAIL.
"""

from __future__ import annotations

import copy

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

from ads_sandbox_egress.dnssec_answer import MessageAuthentication
from ads_sandbox_egress.dnssec_validation import Defect, Failure
from ads_sandbox_egress.policy import RequestDenied

_EDE: dict[Defect, int] = {
    "signature_expired": 7,
    "signature_not_yet_valid": 8,
    "signature_invalid": 6,
    "signature_missing": 10,
    "signer_scope": 6,
    "dnskey_missing": 9,
    "dnskey_flags": 11,
    "dnskey_protocol": 6,
    "ds_mismatch": 6,
}
_SECURITY_RECORDS = frozenset(
    (
        dns.rdatatype.RRSIG,
        dns.rdatatype.DNSKEY,
        dns.rdatatype.DS,
        dns.rdatatype.NSEC,
        dns.rdatatype.NSEC3,
        dns.rdatatype.NSEC3PARAM,
    )
)


def diagnostics(authentication: MessageAuthentication) -> tuple[dns.edns.EDEOption, ...]:
    """Only locally established failures, never irrelevant bad alternatives."""
    if authentication.state != "bogus":
        return ()
    failures: list[Failure] = []
    for record in authentication.records:
        if record.state == "bogus":
            for check in record.checks:
                if not check.valid:
                    failures.extend(check.failures)
    for zone in authentication.zones:
        if zone.state == "bogus":
            for signature in zone.signatures:
                if not signature.valid:
                    failures.extend(signature.failures)
            for delegation in zone.delegations:
                if not delegation.matched:
                    failures.extend(delegation.failures)
    codes = sorted({_EDE[item.defect] for item in failures}) or [6]
    # No upstream strings, private names, key bytes, or exception reprs.
    return tuple(dns.edns.EDEOption(dns.edns.EDECode.make(code)) for code in codes)


def _base(query: dns.message.Message, *, safe_udp_payload: int) -> dns.message.Message:
    if len(query.question) != 1 or not 512 <= safe_udp_payload <= 1232:
        raise RequestDenied("dns_reply_inputs")
    response = dns.message.make_response(query)
    response.flags = dns.flags.QR | dns.flags.RA | (query.flags & (dns.flags.RD | dns.flags.CD))
    if query.edns >= 0:
        response.use_edns(
            edns=0,
            ednsflags=query.ednsflags & dns.flags.DO,
            payload=safe_udp_payload,
        )
    return response


def fallback(
    query: dns.message.Message,
    authentication: MessageAuthentication,
    *,
    safe_udp_payload: int,
) -> dns.message.Message:
    """Faithful construction failed, including when the client set CD."""
    result = _base(query, safe_udp_payload=safe_udp_payload)
    result.set_rcode(dns.rcode.SERVFAIL)
    if query.edns >= 0:
        options = diagnostics(authentication)
        result.use_edns(
            edns=0,
            ednsflags=query.ednsflags & dns.flags.DO,
            payload=safe_udp_payload,
            options=[
                *options,
                dns.edns.EDEOption(
                    dns.edns.EDECode.OTHER, "ADS cannot faithfully construct the DNSSEC view"
                ),
            ],
        )
    return result


def resolution_failure(
    query: dns.message.Message,
    upstream: dns.message.Message | None,
    *,
    safe_udp_payload: int,
) -> dns.message.Message:
    """No usable answer, not a locally verified DNSSEC defect.

    Preserve upstream failure RCODE/EDE codes, but not unbounded/untrusted EDE
    text or OPT options such as cookies tied to the upstream query. The fixed
    diagnostic explicitly identifies upstream-reported (not verified) causes.
    """
    result = _base(query, safe_udp_payload=safe_udp_payload)
    result.set_rcode(dns.rcode.SERVFAIL)
    options: list[dns.edns.Option] = []
    if upstream is not None:
        if upstream.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            raise RequestDenied("not_an_upstream_resolution_failure")
        code = upstream.rcode()
        result.set_rcode(code if query.edns >= 0 or code <= 15 else dns.rcode.SERVFAIL)
        codes = list(
            dict.fromkeys(
                int(option.code)
                for option in upstream.options
                if isinstance(option, dns.edns.EDEOption)
            )
        )
        if len(codes) > 16:
            raise RequestDenied("dns_diagnostic_limit")
        options = [
            dns.edns.EDEOption(dns.edns.EDECode.make(code), "Reported by upstream resolver")
            for code in codes
        ]
    if query.edns >= 0:
        result.use_edns(
            edns=0,
            ednsflags=query.ednsflags & dns.flags.DO,
            payload=safe_udp_payload,
            options=options,
        )
    return result


def render(
    query: dns.message.Message,
    candidate: dns.message.Message,
    authentication: MessageAuthentication,
    *,
    safe_udp_payload: int,
) -> dns.message.Message:
    """Render a previously checked/committed candidate, never raw acquisition."""
    if (
        candidate.question != query.question
        or candidate.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
        or authentication.resolution_failure
        or authentication.state == "indeterminate"
    ):
        raise RequestDenied("unverified_dns_candidate")
    if authentication.state == "bogus" and not query.flags & dns.flags.CD:
        result = _base(query, safe_udp_payload=safe_udp_payload)
        result.set_rcode(dns.rcode.SERVFAIL)
        if query.edns >= 0:
            result.use_edns(
                edns=0,
                ednsflags=query.ednsflags & dns.flags.DO,
                payload=safe_udp_payload,
                options=list(diagnostics(authentication)),
            )
        return result
    result = _base(query, safe_udp_payload=safe_udp_payload)
    result.set_rcode(candidate.rcode())
    wants_security = bool(query.ednsflags & dns.flags.DO)
    explicit_names: set[dns.name.Name] = {query.question[0].name}
    # A requested DNSSEC type remains an answer through a CNAME chain even
    # without DO. Only follow actual aliases, not arbitrary matching types.
    for _ in range(len(candidate.answer)):
        prior = len(explicit_names)
        for rrset in candidate.answer:
            if rrset.rdtype == dns.rdatatype.CNAME and rrset.name in explicit_names:
                explicit_names.update(item.target for item in rrset)
        if len(explicit_names) == prior:
            break
    for source, destination in (
        (candidate.answer, result.answer),
        (candidate.authority, result.authority),
        (candidate.additional, result.additional),
    ):
        for rrset in source:
            if (
                wants_security
                or rrset.rdtype not in _SECURITY_RECORDS
                or (
                    source is candidate.answer
                    and rrset.name in explicit_names
                    and rrset.rdtype == query.question[0].rdtype
                )
            ):
                destination.append(copy.deepcopy(rrset))
    if authentication.state == "secure" and (wants_security or query.flags & dns.flags.AD):
        result.flags |= dns.flags.AD
    return result
