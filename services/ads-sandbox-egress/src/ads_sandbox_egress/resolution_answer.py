"""Assemble acquired alias evidence before classification or substitution.

This is not a sandbox-ready DNS view. No upstream AD, unrelated supplied data,
or local cache absence establishes trust. The caller must classify, transform,
validate and persist the assembled result before rendering it to a sandbox.
"""

from __future__ import annotations

import copy
import math
import time

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.DNAME
import dns.rrset

from ads_sandbox_egress.dnssec_identity import DNSSECUnrepresentable
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import AcquiredAnswer


def assemble(
    acquired: AcquiredAnswer, *, deadline: float, now: float | None = None
) -> dns.message.Message:
    """Return the primary alias chain and terminal answer/proof, not services.

    HTTPS/SVCB target and address subqueries remain separately scoped in
    ``acquired.messages``. Their relationships are not flattened into this
    primary answer. All received data was already inspected during acquisition.
    """
    now = time.monotonic() if now is None else now
    if not math.isfinite(now) or not math.isfinite(deadline) or now >= deadline:
        raise RequestDenied("dns_resolution_deadline")
    if (
        not acquired.messages
        or len(acquired.messages) != len(acquired.received_at)
        or any(not math.isfinite(t) or t > now for t in acquired.received_at)
    ):
        raise DNSSECUnrepresentable("missing acquisition timestamps")
    kind = acquired.query_type
    relevant: dict[dns.name.Name, dns.message.Message] = {}
    for message, received in zip(acquired.messages, acquired.received_at, strict=True):
        if len(message.question) != 1:
            raise RequestDenied("dns_answer_question")
        question = message.question[0]
        if question.rdtype != kind:
            continue
        aged = copy.deepcopy(message)
        for section in (aged.answer, aged.authority, aged.additional):
            for rrset in section:
                # Subtract rounded-up elapsed time so construction cannot
                # lengthen any upstream TTL, including sub-second queue time.
                rrset.ttl = max(0, rrset.ttl - math.ceil(now - received))
        previous = relevant.get(question.name)
        if previous is not None:
            # Repeated service/address branches must not fabricate a snapshot
            # from conflicting observations. Equality ignores TTL by design.
            if previous.rcode() != aged.rcode() or any(
                len(left) != len(right) or any(item not in right for item in left)
                for left, right in (
                    (previous.answer, aged.answer),
                    (previous.authority, aged.authority),
                )
            ):
                raise DNSSECUnrepresentable("conflicting acquired DNS observations")
            # Preserve the oldest dependency bound even for identical answers.
            for section, old in (
                (aged.answer, previous.answer),
                (aged.authority, previous.authority),
            ):
                for rrset in section:
                    rrset.ttl = min(rrset.ttl, next(item.ttl for item in old if item == rrset))
        relevant[question.name] = aged
    query = dns.message.make_query(acquired.query_name, kind, want_dnssec=True)
    result = dns.message.make_response(query)
    result.flags &= ~dns.flags.AD
    current = acquired.query_name
    visited: set[dns.name.Name] = set()
    carried: dns.message.Message | None = None

    def add(destination: list[dns.rrset.RRset], rrset: dns.rrset.RRset) -> None:
        same = [
            item
            for item in destination
            if (item.name, item.rdtype, item.covers) == (rrset.name, rrset.rdtype, rrset.covers)
        ]
        if same:
            if len(same) != 1 or same[0] != rrset:
                raise DNSSECUnrepresentable("conflicting assembled DNS records")
            same[0].ttl = min(same[0].ttl, rrset.ttl)
        else:
            destination.append(copy.deepcopy(rrset))

    def with_signatures(
        destination: list[dns.rrset.RRset],
        rrset: dns.rrset.RRset,
        section: list[dns.rrset.RRset],
    ) -> None:
        add(destination, rrset)
        for sigs in section:
            if (
                sigs.name == rrset.name
                and sigs.rdtype == dns.rdatatype.RRSIG
                and sigs.covers == rrset.rdtype
            ):
                add(destination, sigs)

    while current not in visited:
        if len(visited) >= 64:
            raise RequestDenied("dns_alias_limit")
        visited.add(current)
        found = relevant.get(current, carried)
        if found is None:
            raise DNSSECUnrepresentable("incomplete alias acquisition")
        message = found
        if message.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            # Alias prefix plus SERVFAIL must never be exposed as a usable
            # partial answer. The separate response layer handles diagnostics.
            result.answer.clear()
            result.authority.clear()
            result.set_rcode(message.rcode())
            result.use_edns(options=list(message.options))
            return result
        values = [r for r in message.answer if r.rdtype != dns.rdatatype.RRSIG]
        direct = [
            r
            for r in values
            if r.name == current and (r.rdtype == kind or kind == dns.rdatatype.ANY)
        ]
        cnames = [r for r in values if r.name == current and r.rdtype == dns.rdatatype.CNAME]
        dnames = [
            r
            for r in values
            if r.rdtype == dns.rdatatype.DNAME
            and r.name != current
            and current.is_subdomain(r.name)
        ]
        dname = max(dnames, key=lambda r: len(r.name.labels), default=None)
        if len(cnames) > 1 or (cnames and len(cnames[0]) != 1):
            raise RequestDenied("conflicting_dns_alias")
        if direct and cnames and kind not in (dns.rdatatype.CNAME, dns.rdatatype.ANY):
            raise RequestDenied("conflicting_dns_alias")
        if direct and dname is not None and not cnames:
            raise RequestDenied("conflicting_dns_alias")
        if dname is not None:
            if len(dname) != 1:
                raise RequestDenied("conflicting_dns_alias")
            record = next(iter(dname))
            assert isinstance(record, dns.rdtypes.ANY.DNAME.DNAME)
            try:
                target = current.relativize(dname.name).concatenate(record.target)
            except dns.name.NameTooLong:
                raise DNSSECUnrepresentable("DNAME result exceeds DNS name limit") from None
            if cnames and next(iter(cnames[0])).target != target:
                raise RequestDenied("conflicting_dns_alias")
            with_signatures(result.answer, dname, message.answer)
            if not cnames:
                cnames = [dns.rrset.from_text(current, dname.ttl, "IN", "CNAME", target.to_text())]
            if kind == dns.rdatatype.CNAME:
                direct = cnames
        # Retain actual denial structure for wildcard or terminal negative
        # validation. SOA is relevant only at the terminal response.
        for proof in message.authority:
            if proof.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                with_signatures(result.authority, proof, message.authority)
        if direct:
            if message.rcode() != dns.rcode.NOERROR:
                raise RequestDenied("positive_answer_with_nxdomain")
            for rrset in direct:
                with_signatures(result.answer, rrset, message.answer)
            break
        if cnames:
            with_signatures(result.answer, cnames[0], message.answer)
            cname = next(iter(cnames[0]))
            assert isinstance(cname, dns.rdtypes.ANY.CNAME.CNAME)
            carried = message
            current = cname.target
            continue
        if message.question[0].name != current and not any(
            item.rdtype == dns.rdatatype.SOA for item in message.authority
        ):
            raise DNSSECUnrepresentable("incomplete alias terminal evidence")
        result.set_rcode(message.rcode())
        for rrset in message.authority:
            if rrset.rdtype == dns.rdatatype.SOA:
                with_signatures(result.authority, rrset, message.authority)
        break
    else:
        raise RequestDenied("dns_alias_loop")
    if time.monotonic() >= deadline:
        raise RequestDenied("dns_resolution_deadline")
    return result
