"""Upstream message authentication with retained cryptographic evidence.

This is not synthetic publication or destination authorization. Upstream AD
is ignored, acquisition failures are not cryptographic defects, and an
unproved unsigned answer remains indeterminate. All work uses the caller's
original resolution deadline and cryptographic budget.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.DNAME
import dns.rdtypes.ANY.RRSIG
import dns.rrset

from ads_sandbox_egress.dnssec_chain import PositiveChains, State, ZoneAuthentication
from ads_sandbox_egress.dnssec_denial import DenialProof, Kind, validate_denial
from ads_sandbox_egress.dnssec_validation import (
    CryptoBudget,
    SignatureCheck,
    _bounded,
    check_signatures,
)
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import ResolutionJob


@dataclass(frozen=True, slots=True)
class RecordAuthentication:
    records: dns.rrset.RRset
    state: State
    checks: tuple[SignatureCheck, ...] = ()
    denials: tuple[DenialProof, ...] = ()
    limitation: str | None = None
    # An unsigned protocol-generated CNAME inherits only its verified DNAME.
    synthesized_from: dns.name.Name | None = None


@dataclass(frozen=True, slots=True)
class MessageAuthentication:
    state: State
    records: tuple[RecordAuthentication, ...]
    zones: tuple[ZoneAuthentication, ...]
    denials: tuple[DenialProof, ...] = ()
    limitation: str | None = None
    resolution_failure: bool = False
    discovery_messages: tuple[dns.message.Message, ...] = ()


def _combined(states: list[State]) -> State:
    """Conjunction of required RRsets, unlike alternative-signature paths."""
    if "bogus" in states:
        return "bogus"
    if not states or "indeterminate" in states:
        return "indeterminate"
    if "insecure" in states:
        return "insecure"
    return "secure"


class AnswerAuthentication:
    def __init__(self, chains: PositiveChains) -> None:
        self.chains = chains

    async def classify(
        self,
        message: dns.message.Message,
        job: ResolutionJob,
        *,
        budget: CryptoBudget,
    ) -> MessageAuthentication:
        """Classify one acquired query response, not an assembled alias result.

        A resolution owner must classify every required acquired message.
        Returned records remain original evidence, never a ready-to-send
        synthetic answer. Additional data is inspected but cannot establish
        an answer's authentication or supply a trusted key.
        """
        if (
            len(message.question) != 1
            or not message.flags & dns.flags.QR
            or message.flags & dns.flags.TC
            or message.opcode() != dns.opcode.QUERY
            or message.question[0].rdclass != dns.rdataclass.IN
            or not message.question[0].name.is_absolute()
        ):
            raise RequestDenied("dnssec_answer_question")
        self.chains.resolver.inspect(message)
        question = message.question[0]
        zones: dict[dns.name.Name, ZoneAuthentication] = {}
        records: list[RecordAuthentication] = []
        discovery: dict[dns.name.Name, ZoneAuthentication | None] = {}
        discovery_messages: list[dns.message.Message] = []
        discovery_proofs: list[DenialProof] = []

        def result(
            state: State,
            *,
            denials: tuple[DenialProof, ...] = (),
            limitation: str | None = None,
            resolution_failure: bool = False,
        ) -> MessageAuthentication:
            if time.monotonic() >= job.deadline:
                raise RequestDenied("dns_resolution_deadline")
            return MessageAuthentication(
                state,
                tuple(records),
                tuple(zones.values()),
                (*discovery_proofs, *denials),
                limitation,
                resolution_failure,
                tuple(discovery_messages),
            )

        if message.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            return result(
                "indeterminate", limitation="upstream_resolution_failure", resolution_failure=True
            )
        if len(message.answer) + len(message.authority) > 128:
            raise RequestDenied("dnssec_answer_rrset_limit")

        async def zone(name: dns.name.Name) -> ZoneAuthentication:
            name = name.canonicalize()
            if name not in zones:
                zones[name] = await self.chains.authenticate(name, job, budget=budget)
            return zones[name]

        def signatures(
            rrset: dns.rrset.RRset, section: list[dns.rrset.RRset]
        ) -> dns.rrset.RRset | None:
            found = [
                item
                for item in section
                if item.name == rrset.name
                and item.rdtype == dns.rdatatype.RRSIG
                and item.covers == rrset.rdtype
            ]
            if len(found) > 1:
                raise RequestDenied("dnssec_ambiguous_signatures")
            return found[0] if found else None

        def proof_sets(
            name: dns.name.Name,
        ) -> tuple[tuple[dns.rrset.RRset, dns.rrset.RRset | None], ...]:
            return tuple(
                (item, signatures(item, message.authority))
                for item in message.authority
                if item.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
                and item.name.is_subdomain(name)
            )

        async def establish(
            name: dns.name.Name, auth: ZoneAuthentication
        ) -> ZoneAuthentication | None:
            """Prove every possible closer cut; no suffix/registrable guess."""
            candidates = [
                dns.name.Name(name.labels[-length:])
                for length in range(len(auth.zone.labels) + 1, len(name.labels) + 1)
            ]
            if len(candidates) > 32:
                raise RequestDenied("dnssec_chain_depth_or_cycle")
            for candidate in candidates:
                if auth.state != "secure" or auth.trusted_keys is None:
                    return auth
                trusted = auth.trusted_keys
                found = await self.chains.resolver.exchange(candidate, dns.rdatatype.DS, job)
                discovery_messages.append(found)
                if found.rcode() != dns.rcode.NOERROR:
                    return None
                ds = [
                    item
                    for item in found.answer
                    if item.name == candidate and item.rdtype == dns.rdatatype.DS
                ]
                if len(ds) > 1:
                    return None
                if ds:
                    checked = check_signatures(
                        ds[0],
                        signatures(ds[0], found.answer),
                        trusted,
                        now=time.time(),
                        budget=budget,
                    )
                    if not any(not path.wildcard for path in checked.verified):
                        return None
                    auth = await zone(candidate)
                    continue
                evidence = tuple(
                    (item, signatures(item, found.authority))
                    for item in found.authority
                    if item.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
                    and item.name.is_subdomain(auth.zone)
                )
                unsigned = validate_denial(
                    candidate,
                    dns.rdatatype.DS,
                    "unsigned_delegation",
                    evidence,
                    trusted,
                    now=time.time(),
                    budget=budget,
                )
                discovery_proofs.append(unsigned)
                if unsigned.valid:
                    # The parent's authenticated proof, not the SOA hint,
                    # establishes the first insecure boundary.
                    insecure = ZoneAuthentication(
                        candidate, "insecure", messages=(found,), denials=(unsigned,)
                    )
                    zones[candidate] = insecure
                    return insecure
                absent_ds = validate_denial(
                    candidate,
                    dns.rdatatype.DS,
                    "nodata",
                    evidence,
                    trusted,
                    now=time.time(),
                    budget=budget,
                )
                discovery_proofs.append(absent_ds)
                if not absent_ds.valid or absent_ds.opt_out:
                    return None
            return auth

        async def check(
            rrset: dns.rrset.RRset, section: list[dns.rrset.RRset]
        ) -> RecordAuthentication:
            _bounded(rrset)
            sigs = signatures(rrset, section)
            if sigs is None:
                # SOA locates a candidate, but is NOT itself an insecurity
                # proof. Independently authenticate that candidate's parent
                # no-DS delegation before accepting unsigned descendants.
                if rrset.name not in discovery:
                    found = await self.chains.resolver.exchange(rrset.name, dns.rdatatype.SOA, job)
                    discovery_messages.append(found)
                    candidates = {
                        item.name
                        for item in (*found.answer, *found.authority)
                        if item.rdtype == dns.rdatatype.SOA and rrset.name.is_subdomain(item.name)
                    }
                    candidate = next(iter(candidates)) if len(candidates) == 1 else None
                    anchor = self.chains.closest_anchor(rrset.name)
                    if (
                        found.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
                        and candidate is not None
                        and not (
                            anchor is not None
                            and anchor != candidate
                            and anchor.is_subdomain(candidate)
                        )
                    ):
                        candidate_auth = await zone(candidate)
                        discovery[rrset.name] = await establish(rrset.name, candidate_auth)
                    else:
                        discovery[rrset.name] = None
                discovered = discovery[rrset.name]
                if discovered is not None:
                    if discovered.state == "insecure":
                        return RecordAuthentication(rrset, "insecure")
                    if (
                        discovered.state == "secure"
                        and rrset.rdtype != dns.rdatatype.DS
                        and discovered.trusted_keys is not None
                    ):
                        # Authenticated non-cut proofs ruled out every closer
                        # unsigned delegation. Parent-side DS remains separate.
                        checked = check_signatures(
                            rrset, None, discovered.trusted_keys, now=time.time(), budget=budget
                        )
                        return RecordAuthentication(rrset, "bogus", (checked,))
                # Incomplete discovery is not an unsigned-zone assertion.
                return RecordAuthentication(
                    rrset, "indeterminate", limitation="signing_expectation_unestablished"
                )
            _bounded(sigs, maximum=64)
            names = tuple(
                dict.fromkeys(
                    sig.signer
                    for sig in sigs
                    if isinstance(sig, dns.rdtypes.ANY.RRSIG.RRSIG)
                    and rrset.name.is_subdomain(sig.signer)
                )
            )
            checks: list[SignatureCheck] = []
            proofs: list[DenialProof] = []
            states: list[State] = []
            success = False
            for name in names:
                anchor = self.chains.closest_anchor(rrset.name)
                if anchor is not None and anchor != name and anchor.is_subdomain(name):
                    states.append("indeterminate")
                    continue
                auth = await zone(name)
                if auth.state != "secure" or auth.trusted_keys is None:
                    states.append(auth.state)
                    continue
                applicable = dns.rrset.from_rdata(
                    sigs.name, sigs.ttl, *(sig for sig in sigs if sig.signer == name)
                )
                checked = check_signatures(
                    rrset, applicable, auth.trusted_keys, now=time.time(), budget=budget
                )
                checks.append(checked)
                valid = any(not path.wildcard for path in checked.verified)
                insecure_proof = False
                uncertain = bool(checked.limitations) or bool(
                    checked.unsupported and not checked.failures
                )
                for path in checked.verified:
                    if not path.wildcard:
                        continue
                    # DNAME is not usable from a wildcard (RFC 6672 3.3).
                    if rrset.rdtype == dns.rdatatype.DNAME:
                        uncertain = True
                        continue
                    wildcard = dns.name.Name(
                        (b"*",) + rrset.name.labels[-path.signature.labels - 1 :]
                    )
                    proof = validate_denial(
                        rrset.name,
                        rrset.rdtype,
                        "wildcard",
                        proof_sets(name),
                        auth.trusted_keys,
                        now=time.time(),
                        budget=budget,
                        wildcard=wildcard,
                    )
                    proofs.append(proof)
                    if proof.valid:
                        if proof.opt_out:
                            insecure_proof = True
                        else:
                            valid = True
                if valid:
                    success = True
                elif insecure_proof:
                    states.append("insecure")
                else:
                    states.append("indeterminate" if uncertain else "bogus")
            # A valid alternative is enough. Untrusted alternate signers or
            # an expired additional signature cannot erase an authenticated path.
            state: State = (
                "secure"
                if success
                else "bogus"
                if checks and "bogus" in states
                else "indeterminate"
                if not states or "indeterminate" in states
                else "bogus"
                if "bogus" in states
                else "insecure"
            )
            return RecordAuthentication(rrset, state, tuple(checks), tuple(proofs))

        supplied = [item for item in message.answer if item.rdtype != dns.rdatatype.RRSIG]
        identities = [(item.name, item.rdtype) for item in supplied]
        if len(set(identities)) != len(identities):
            raise RequestDenied("dnssec_ambiguous_answer")
        # Unrelated signed data is not proof of this query. Follow only the
        # actual answer/alias relationship; inspect() already checked all data.
        answer: list[dns.rrset.RRset] = []
        current = question.name
        visited: set[dns.name.Name] = set()
        terminal = False
        while current not in visited:
            if len(visited) > self.chains.resolver.limits.aliases:
                raise RequestDenied("dns_alias_limit")
            visited.add(current)
            direct = [
                item
                for item in supplied
                if item.name == current
                and (item.rdtype == question.rdtype or question.rdtype == dns.rdatatype.ANY)
            ]
            cnames = [
                item
                for item in supplied
                if item.name == current and item.rdtype == dns.rdatatype.CNAME
            ]
            dnames = [
                item
                for item in supplied
                if item.rdtype == dns.rdatatype.DNAME
                and item.name != current
                and current.is_subdomain(item.name)
            ]
            if direct:
                if cnames and question.rdtype not in (dns.rdatatype.CNAME, dns.rdatatype.ANY):
                    raise RequestDenied("conflicting_dns_alias")
                if cnames and any(
                    item.rdtype
                    not in (dns.rdatatype.CNAME, dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
                    for item in direct
                ):
                    raise RequestDenied("conflicting_dns_alias")
                if dnames and not cnames:
                    raise RequestDenied("conflicting_dns_alias")
                if dnames:
                    answer.append(max(dnames, key=lambda item: len(item.name.labels)))
                answer.extend(item for item in direct if item not in answer)
                terminal = True
                break
            if cnames:
                cname_set = cnames[0]
                if len(cname_set) != 1:
                    raise RequestDenied("conflicting_dns_alias")
                cname = next(iter(cname_set))
                assert isinstance(cname, dns.rdtypes.ANY.CNAME.CNAME)
                if dnames:
                    dname_set = max(dnames, key=lambda item: len(item.name.labels))
                    if dname_set not in answer:
                        answer.append(dname_set)
                answer.append(cname_set)
                current = cname.target
            elif dnames:
                # RFC 6672 response requires the synthesized CNAME too.
                return result("indeterminate", limitation="dname_synthesis_missing")
            else:
                break
        else:
            raise RequestDenied("dns_alias_loop")
        for rrset in answer:
            if rrset.rdtype != dns.rdatatype.CNAME:
                records.append(await check(rrset, message.answer))
        for rrset in answer:
            if rrset.rdtype != dns.rdatatype.CNAME:
                continue
            parents = [
                item
                for item in records
                if item.records.rdtype == dns.rdatatype.DNAME
                and rrset.name != item.records.name
                and rrset.name.is_subdomain(item.records.name)
            ]
            parent = max(parents, key=lambda item: len(item.records.name.labels), default=None)
            if parent is not None:
                matches = False
                if len(rrset) == len(parent.records) == 1:
                    cname, dname = next(iter(rrset)), next(iter(parent.records))
                    if isinstance(cname, dns.rdtypes.ANY.CNAME.CNAME) and isinstance(
                        dname, dns.rdtypes.ANY.DNAME.DNAME
                    ):
                        try:
                            expected = rrset.name.relativize(parent.records.name).concatenate(
                                dname.target
                            )
                            matches = cname.target == expected
                        except dns.name.NameTooLong:
                            pass
                if not matches or signatures(rrset, message.answer) is None:
                    records.append(
                        RecordAuthentication(
                            rrset,
                            parent.state if matches else "bogus",
                            limitation=None if matches else "invalid_dname_synthesis",
                            synthesized_from=parent.records.name,
                        )
                    )
                    continue
            records.append(await check(rrset, message.answer))

        if terminal:
            if message.rcode() == dns.rcode.NXDOMAIN:
                raise RequestDenied("positive_answer_with_nxdomain")
            return result(_combined([item.state for item in records]))

        soa = [item for item in message.authority if item.rdtype == dns.rdatatype.SOA]
        if len(soa) != 1 or not current.is_subdomain(soa[0].name):
            return result("indeterminate", limitation="negative_zone_evidence_required")
        soa_auth = await check(soa[0], message.authority)
        records.append(soa_auth)
        if soa_auth.state != "secure":
            return result(
                _combined([item.state for item in records]),
                limitation="negative_soa_not_authenticated",
            )
        auth = zones.get(soa[0].name)
        if auth is None or auth.trusted_keys is None:
            return result("indeterminate", limitation="negative_soa_zone_mismatch")
        negative = []
        kinds: tuple[Kind, ...] = (
            ("nxdomain",)
            if message.rcode() == dns.rcode.NXDOMAIN
            else ("nodata", "wildcard_nodata")
        )
        for kind in kinds:
            proof = validate_denial(
                current,
                question.rdtype,
                kind,
                proof_sets(soa[0].name),
                auth.trusted_keys,
                now=time.time(),
                budget=budget,
            )
            negative.append(proof)
            if proof.valid:
                return result(
                    _combined(
                        [item.state for item in records]
                        + ["insecure" if proof.opt_out else "secure"]
                    ),
                    denials=tuple(negative),
                )
        return result("bogus", denials=tuple(negative), limitation="negative_proof_invalid")
