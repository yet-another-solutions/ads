"""Fresh DNSSEC key-chain acquisition against explicit upstream anchors.

This component follows signed DS evidence, never guessed registrable domains.
Authenticated no-DS delegation proofs may establish insecurity, including
signed islands. Missing or unusable evidence remains indeterminate. It neither
synthesizes records nor authenticates complete answers. No persistent cache.
"""

from __future__ import annotations

import copy
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.RRSIG
import dns.rrset

from ads_sandbox_egress.dnssec_denial import DenialProof, validate_denial
from ads_sandbox_egress.dnssec_validation import (
    CryptoBudget,
    DSCheck,
    SignatureCheck,
    _bounded,
    check_ds,
    check_signatures,
)
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import ResolutionJob, UpstreamResolver

State = Literal["secure", "insecure", "bogus", "indeterminate"]


@dataclass(frozen=True, slots=True)
class ZoneAuthentication:
    zone: dns.name.Name
    state: State
    # Only secure has trusted keys. Other states retain messages for eventual
    # faithful synthesis/diagnostics, never as authentication input.
    trusted_keys: dns.rrset.RRset | None = None
    messages: tuple[dns.message.Message, ...] = ()
    signatures: tuple[SignatureCheck, ...] = ()
    delegations: tuple[DSCheck, ...] = ()
    limitation: str | None = None
    denials: tuple[DenialProof, ...] = ()


def exact(
    message: dns.message.Message,
    name: dns.name.Name,
    kind: dns.rdatatype.RdataType,
    *,
    covers: dns.rdatatype.RdataType = dns.rdatatype.NONE,
) -> dns.rrset.RRset | None:
    """No alias/name fallback; ambiguity is missing usable proof, never absence."""
    found = [
        rrset
        for rrset in message.answer
        if rrset.name == name and rrset.rdtype == kind and rrset.covers == covers
    ]
    return found[0] if len(found) == 1 else None


class PositiveChains:
    def __init__(
        self, resolver: UpstreamResolver, upstream_anchors: Mapping[dns.name.Name, dns.rrset.RRset]
    ) -> None:
        if not upstream_anchors or len(upstream_anchors) > 16:
            raise ValueError("explicit bounded upstream DNSSEC anchors required")
        self.resolver = resolver
        anchors = {}
        for name, anchor in upstream_anchors.items():
            _bounded(anchor, maximum=64)
            if (
                name != anchor.name
                or not anchor
                or anchor.rdtype not in (dns.rdatatype.DS, dns.rdatatype.DNSKEY)
            ):
                raise ValueError("invalid upstream anchor scope")
            anchors[name.canonicalize()] = copy.deepcopy(anchor)
        # This input must come from upstream trust configuration, NEVER the
        # sandbox IdentityStore or its generated DNSSEC root.
        self._anchors = anchors

    def closest_anchor(self, name: dns.name.Name) -> dns.name.Name | None:
        """Most-specific configured trust boundary, without exposing key state."""
        return max(
            (anchor for anchor in self._anchors if name.is_subdomain(anchor)),
            key=lambda anchor: len(anchor.labels),
            default=None,
        )

    async def authenticate(
        self, zone: dns.name.Name, job: ResolutionJob, *, budget: CryptoBudget
    ) -> ZoneAuthentication:
        if not zone.is_absolute():
            raise ValueError("absolute observed signer required")
        # Memo is request-local and discarded even on failure. Each new
        # resolution obtains new evidence with its existing original deadline.
        memo: dict[dns.name.Name, ZoneAuthentication] = {}
        return await self._zone(zone.canonicalize(), job, budget, memo, frozenset())

    async def _zone(
        self,
        zone: dns.name.Name,
        job: ResolutionJob,
        budget: CryptoBudget,
        memo: dict[dns.name.Name, ZoneAuthentication],
        visiting: frozenset[dns.name.Name],
    ) -> ZoneAuthentication:
        if zone in memo:
            return memo[zone]
        if zone in visiting or len(visiting) >= 32:
            raise RequestDenied("dnssec_chain_depth_or_cycle")
        visiting = visiting | {zone}
        message = await self.resolver.exchange(zone, dns.rdatatype.DNSKEY, job)
        messages = {id(message): message}
        keys = exact(message, zone, dns.rdatatype.DNSKEY)
        sigs = exact(message, zone, dns.rdatatype.RRSIG, covers=dns.rdatatype.DNSKEY)
        checks: dict[int, SignatureCheck] = {}
        ds_checks: dict[int, DSCheck] = {}
        denials: dict[int, DenialProof] = {}

        def result(
            state: State, trusted: dns.rrset.RRset | None = None, limitation: str | None = None
        ) -> ZoneAuthentication:
            if time.monotonic() >= job.deadline:
                raise RequestDenied("dns_resolution_deadline")
            value = ZoneAuthentication(
                zone,
                state,
                trusted,
                tuple(messages.values()),
                tuple(checks.values()),
                tuple(ds_checks.values()),
                limitation,
                tuple(denials.values()),
            )
            memo[zone] = value
            return value

        if message.rcode() != dns.rcode.NOERROR:
            return result("indeterminate", limitation="dnskey_resolution_failure")
        if keys is not None:
            _bounded(keys, maximum=64)
        if zone in self._anchors:
            if keys is None or not keys:
                return result("indeterminate", limitation="anchor_dnskey_absence_requires_proof")
            anchor = self._anchors[zone]
            if anchor.rdtype == dns.rdatatype.DS:
                matched = check_ds(anchor, keys, budget=budget)
                ds_checks[id(matched)] = matched
                candidates = matched.matched
                if not matched.supported_paths:
                    # A configured unusable anchor is not an insecure delegation.
                    return result("indeterminate", limitation="unsupported_upstream_anchor")
            else:
                candidates = tuple(key for key in keys if key in anchor)
            if not candidates:
                return result("bogus", limitation="anchor_key_mismatch")
            trusted = dns.rrset.from_rdata(zone, keys.ttl, *candidates)
            checked = check_signatures(keys, sigs, trusted, now=time.time(), budget=budget)
            checks[id(checked)] = checked
            if any(not path.wildcard for path in checked.verified):
                return result("secure", keys)
            return result(
                "indeterminate"
                if checked.limitations
                or checked.valid
                or checked.unsupported
                and not checked.failures
                else "bogus",
                limitation="anchor_dnskey_verification",
            )

        delegation = await self.resolver.exchange(zone, dns.rdatatype.DS, job)
        messages[id(delegation)] = delegation
        ds = exact(delegation, zone, dns.rdatatype.DS)
        ds_sigs = exact(delegation, zone, dns.rdatatype.RRSIG, covers=dns.rdatatype.DS)
        if delegation.rcode() != dns.rcode.NOERROR:
            return result("indeterminate", limitation="delegation_resolution_failure")
        if ds is None or not ds:
            # No DS is not enough. Only a verified parent denial proof can
            # establish an insecure delegation, even if child keys are absent.
            proof_sets = tuple(
                item
                for item in delegation.authority
                if item.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
            )
            if len(proof_sets) > 64:
                raise RequestDenied("dnssec_denial_scope_or_limit")
            parent_names: dict[dns.name.Name, None] = {}
            for signatures in delegation.authority:
                if signatures.rdtype == dns.rdatatype.RRSIG and signatures.covers in (
                    dns.rdatatype.NSEC,
                    dns.rdatatype.NSEC3,
                ):
                    _bounded(signatures, maximum=64)
                    for sig in signatures:
                        if isinstance(sig, dns.rdtypes.ANY.RRSIG.RRSIG) and (
                            sig.signer != zone and zone.is_subdomain(sig.signer)
                        ):
                            parent_names[sig.signer] = None
            for parent in parent_names:
                parent_auth = await self._zone(parent, job, budget, memo, visiting)
                messages.update((id(value), value) for value in parent_auth.messages)
                checks.update((id(value), value) for value in parent_auth.signatures)
                ds_checks.update((id(value), value) for value in parent_auth.delegations)
                denials.update((id(value), value) for value in parent_auth.denials)
                if parent_auth.state != "secure" or parent_auth.trusted_keys is None:
                    continue
                evidence = []
                for rrset in proof_sets:
                    if not rrset.name.is_subdomain(parent):
                        continue
                    sigsets = [
                        item
                        for item in delegation.authority
                        if item.name == rrset.name
                        and item.rdtype == dns.rdatatype.RRSIG
                        and item.covers == rrset.rdtype
                    ]
                    evidence.append((rrset, sigsets[0] if len(sigsets) == 1 else None))
                proof = validate_denial(
                    zone,
                    dns.rdatatype.DS,
                    "unsigned_delegation",
                    tuple(evidence),
                    parent_auth.trusted_keys,
                    now=time.time(),
                    budget=budget,
                )
                denials[id(proof)] = proof
                if proof.valid:
                    return result("insecure")
            # Cannot conclude bogus merely because an untrusted signer claimed
            # a parent. Zone discovery/expected-proof processing is separate.
            return result("indeterminate", limitation="delegation_absence_requires_proof")
        if ds_sigs is None:
            return result("indeterminate", limitation="delegation_signature_requires_parent")
        if keys is None or not keys:
            return result("indeterminate", limitation="dnskey_absence_requires_proof")
        _bounded(ds_sigs, maximum=64)
        parents = tuple(
            dict.fromkeys(
                sig.signer.canonicalize()
                for sig in ds_sigs
                if isinstance(sig, dns.rdtypes.ANY.RRSIG.RRSIG)
                and sig.signer != zone
                and zone.is_subdomain(sig.signer)
            )
        )
        if not parents:
            return result("indeterminate", limitation="no_observed_parent_signer")
        parent_states: list[State] = []
        for parent in parents:
            parent_auth = await self._zone(parent, job, budget, memo, visiting)
            parent_states.append(parent_auth.state)
            # Alternate signers can share ancestors. Keep one reference per
            # acquired/checked object rather than exponential path duplication.
            messages.update((id(value), value) for value in parent_auth.messages)
            checks.update((id(value), value) for value in parent_auth.signatures)
            ds_checks.update((id(value), value) for value in parent_auth.delegations)
            denials.update((id(value), value) for value in parent_auth.denials)
            if parent_auth.state != "secure" or parent_auth.trusted_keys is None:
                continue
            ds_checked = check_signatures(
                ds, ds_sigs, parent_auth.trusted_keys, now=time.time(), budget=budget
            )
            checks[id(ds_checked)] = ds_checked
            if not any(not path.wildcard for path in ds_checked.verified):
                continue
            matched = check_ds(ds, keys, budget=budget)
            ds_checks[id(matched)] = matched
            if not matched.supported_paths:
                # This is authenticated POSITIVE DS evidence containing only
                # locally unsupported paths, not an inference from absent data.
                return result("insecure", limitation="unsupported_only_delegation")
            if not matched.matched:
                return result("bogus", limitation="delegation_key_mismatch")
            selected = dns.rrset.from_rdata(zone, keys.ttl, *matched.matched)
            checked = check_signatures(keys, sigs, selected, now=time.time(), budget=budget)
            checks[id(checked)] = checked
            if any(not path.wildcard for path in checked.verified):
                return result("secure", keys)
            return result(
                "indeterminate"
                if checked.limitations
                or checked.valid
                or checked.unsupported
                and not checked.failures
                else "bogus",
                limitation="child_dnskey_verification",
            )
        if "indeterminate" in parent_states or any(
            c.limitations or c.valid and all(p.wildcard for p in c.verified)
            for c in checks.values()
        ):
            return result("indeterminate", limitation="parent_evidence_incomplete")
        if "insecure" in parent_states:
            return result("indeterminate", limitation="unsigned_chain_processing_required")
        return result("bogus", limitation="no_valid_parent_path")
