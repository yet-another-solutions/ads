"""Bounded DNSSEC substitutions, without publication or invented zone trust.

The view owner supplies acquired full DNSKEY sets and inspected RRsets. This
component preserves cryptographic outcomes; it does not establish delegation
trust, authorize addresses, or turn a signed island into an authenticated zone.
Every candidate is checked before it is returned. Unsupported constructions
raise a local synthesis limitation, never a fabricated upstream diagnosis.
"""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass

import dns.dnssec
import dns.dnssecalgs
import dns.exception
import dns.name
import dns.rdatatype
import dns.rdtypes.ANY.RRSIG
import dns.rrset

from ads_sandbox_egress.dnssec_denial import DenialProof, Kind, validate_denial
from ads_sandbox_egress.dnssec_identity import (
    DNSKey,
    DNSSECIdentities,
    DNSSECUnrepresentable,
    SigningIdentity,
)
from ads_sandbox_egress.dnssec_validation import (
    DS,
    CryptoBudget,
    DSCheck,
    SignatureCheck,
    _bounded,
    check_ds,
    check_signatures,
    fingerprint,
)
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import ResolutionJob


@dataclass(frozen=True, slots=True)
class KeySubstitution:
    original: dns.rrset.RRset
    synthetic: dns.rrset.RRset
    identities: tuple[SigningIdentity, ...]

    def for_key(self, original: DNSKey) -> SigningIdentity:
        for key, identity in zip(self.original, self.identities, strict=True):
            if key == original:
                return identity
        raise DNSSECUnrepresentable("DNSKEY not in acquired substitution")


@dataclass(frozen=True, slots=True)
class SignatureSubstitution:
    signatures: dns.rrset.RRset | None
    before: SignatureCheck
    after: SignatureCheck


@dataclass(frozen=True, slots=True)
class DelegationSubstitution:
    records: dns.rrset.RRset
    before: DSCheck
    after: DSCheck


@dataclass(frozen=True, slots=True)
class DenialSubstitution:
    evidence: tuple[tuple[dns.rrset.RRset, dns.rrset.RRset | None], ...]
    before: DenialProof
    after: DenialProof


def _defects(check: SignatureCheck | DSCheck) -> tuple[str, ...]:
    # Counts retain failures across colliding candidate paths. Fingerprints
    # necessarily change during substitution and are not outcome categories.
    return tuple(sorted(failure.defect for failure in check.failures))


def _corrupt(value: bytes) -> bytes:
    if not value:
        raise DNSSECUnrepresentable("empty cryptographic value")
    return bytes((value[0] ^ 1,)) + value[1:]


def _absent_tag(keys: KeySubstitution, algorithm: int, original: int) -> int:
    """Preserve absent-key structure, including accidental substitute tag collisions."""
    occupied = {dns.dnssec.key_id(key) for key in keys.synthetic if key.algorithm == algorithm}
    # At most 64 mapped keys; a missing tag always exists without new key material.
    for offset in range(len(occupied) + 1):
        candidate = (original + offset) % 65536
        if candidate not in occupied:
            return candidate
    raise DNSSECUnrepresentable("no absent DNSKEY tag")


class DNSSECTransformer:
    def __init__(
        self, identities: DNSSECIdentities, job: ResolutionJob, budget: CryptoBudget
    ) -> None:
        self.identities, self.job, self.budget = identities, job, budget

    def _deadline(self) -> None:
        if time.monotonic() >= self.job.deadline:
            raise RequestDenied("dns_resolution_deadline")

    def keys(self, original: dns.rrset.RRset) -> KeySubstitution:
        self._deadline()
        _bounded(original, maximum=64)
        if original.rdtype != dns.rdatatype.DNSKEY or not original:
            raise DNSSECUnrepresentable("complete DNSKEY set required")
        mapped = []
        for key in original:
            if not isinstance(key, DNSKey):
                raise DNSSECUnrepresentable("unexpected DNSKEY representation")
            try:
                dns.dnssecalgs.get_algorithm_cls_from_dnskey(key).public_cls.from_dnskey(key)
            except (ValueError, dns.exception.UnsupportedAlgorithm):
                raise DNSSECUnrepresentable("unusable upstream DNSKEY material") from None
            # Charge key-generation work, not only signature verification.
            self.budget.consume()
            mapped.append(self.identities.observed(original.name, key))
            self._deadline()
        synthetic = dns.rrset.from_rdata(
            original.name, original.ttl, *(identity.dnskey for identity in mapped)
        )
        # A new short-tag collision could introduce a usable path absent from
        # the original. Refuse that construction; never collapse full keys.
        tags = [(key.algorithm, dns.dnssec.key_id(key)) for key in synthetic]
        if len(set(tags)) != len(tags):
            raise DNSSECUnrepresentable("synthetic DNSKEY tag collision")
        return KeySubstitution(copy.deepcopy(original), synthetic, tuple(mapped))

    def signatures(
        self,
        original: dns.rrset.RRset,
        synthetic: dns.rrset.RRset,
        signatures: dns.rrset.RRset | None,
        keys: KeySubstitution,
        *,
        now: float,
    ) -> SignatureSubstitution:
        self._deadline()
        _bounded(synthetic)
        if (original.name, original.rdclass, original.rdtype) != (
            synthetic.name,
            synthetic.rdclass,
            synthetic.rdtype,
        ):
            raise DNSSECUnrepresentable("RRset substitution changed scope")
        before = check_signatures(original, signatures, keys.original, now=now, budget=self.budget)
        if before.unsupported or before.limitations:
            raise DNSSECUnrepresentable("signature algorithm or serial interval unsupported")
        converted = []
        for signature in signatures or ():
            assert isinstance(signature, dns.rdtypes.ANY.RRSIG.RRSIG)
            candidates = [
                key
                for key in keys.original
                if key.algorithm == signature.algorithm
                and dns.dnssec.key_id(key) == signature.key_tag
            ]
            if signature.signer != keys.original.name or len(candidates) > 1:
                raise DNSSECUnrepresentable("ambiguous signature key or signer scope")
            if not candidates:
                # Keep the signature's bytes and defects without claiming to
                # sign as a missing key. Avoid introducing a candidate solely
                # because a generated substitute happens to share its short tag.
                absent = signature.replace(
                    key_tag=_absent_tag(keys, signature.algorithm, signature.key_tag)
                )
                assert isinstance(absent, dns.rdtypes.ANY.RRSIG.RRSIG)
                converted.append(absent)
                continue
            identity = keys.for_key(candidates[0])
            signing_set = copy.deepcopy(synthetic)
            signing_set.ttl = signature.original_ttl
            if signature.labels > len(signing_set.name.labels) - 1:
                raise DNSSECUnrepresentable("invalid RRSIG label scope")
            if signature.labels < len(signing_set.name.labels) - 1:
                signing_set.name = dns.name.Name(
                    (b"*",) + signing_set.name.labels[-signature.labels - 1 :]
                )
            self.budget.consume()
            converted_signature = identity.sign(
                signing_set,
                inception=signature.inception,
                expiration=signature.expiration,
            )
            if converted_signature.labels != signature.labels:
                raise DNSSECUnrepresentable("wildcard signature label mismatch")
            if any(
                failure.record == fingerprint(signature) and failure.defect == "signature_invalid"
                for failure in before.failures
            ):
                damaged_signature = converted_signature.replace(
                    signature=_corrupt(converted_signature.signature)
                )
                assert isinstance(damaged_signature, dns.rdtypes.ANY.RRSIG.RRSIG)
                converted_signature = damaged_signature
            converted.append(converted_signature)
            self._deadline()
        result = (
            dns.rrset.from_rdata(signatures.name, signatures.ttl, *converted)
            if signatures is not None and converted
            else None
        )
        after = check_signatures(synthetic, result, keys.synthetic, now=now, budget=self.budget)
        if (
            before.valid != after.valid
            or len(before.verified) != len(after.verified)
            or _defects(before) != _defects(after)
            or after.unsupported
            or after.limitations
        ):
            raise DNSSECUnrepresentable("signature outcome changed during substitution")
        self._deadline()
        return SignatureSubstitution(result, before, after)

    def delegation(
        self, original: dns.rrset.RRset, keys: KeySubstitution
    ) -> DelegationSubstitution:
        self._deadline()
        before = check_ds(original, keys.original, budget=self.budget)
        if before.unsupported:
            # Random digests would change outcomes for validators supporting
            # a different algorithm set.
            raise DNSSECUnrepresentable("unsupported delegation construction")
        converted = []
        for delegation in original:
            assert isinstance(delegation, DS)
            candidates = [
                key
                for key in keys.original
                if key.algorithm == delegation.algorithm
                and dns.dnssec.key_id(key) == delegation.key_tag
            ]
            if len(candidates) > 1:
                raise DNSSECUnrepresentable("ambiguous delegation key")
            if not candidates:
                absent = delegation.replace(
                    key_tag=_absent_tag(keys, delegation.algorithm, delegation.key_tag)
                )
                assert isinstance(absent, DS)
                converted.append(absent)
                continue
            key = candidates[0]
            self.budget.consume(2)
            expected = dns.dnssec.make_ds(
                original.name, key, delegation.digest_type, validating=True
            )
            transformed = dns.dnssec.make_ds(
                original.name,
                keys.for_key(key).dnskey,
                delegation.digest_type,
                validating=True,
            )
            if expected != delegation:
                damaged_delegation = transformed.replace(digest=_corrupt(transformed.digest))
                assert isinstance(damaged_delegation, DS)
                transformed = damaged_delegation
            converted.append(transformed)
            self._deadline()
        result = dns.rrset.from_rdata(original.name, original.ttl, *converted)
        after = check_ds(result, keys.synthetic, budget=self.budget)
        if (
            len(before.matched) != len(after.matched)
            or before.supported_paths != after.supported_paths
            or _defects(before) != _defects(after)
            or after.unsupported
        ):
            raise DNSSECUnrepresentable("delegation outcome changed during substitution")
        self._deadline()
        return DelegationSubstitution(result, before, after)

    def denial(
        self,
        qname: dns.name.Name,
        qtype: dns.rdatatype.RdataType,
        kind: Kind,
        evidence: tuple[tuple[dns.rrset.RRset, dns.rrset.RRset | None], ...],
        keys: KeySubstitution,
        *,
        now: float,
        wildcard: dns.name.Name | None = None,
    ) -> DenialSubstitution:
        """Retain acquired NSEC/NSEC3 structure, including defects and Opt-Out.

        Mapping keys does not change names, hashes, bitmaps or denial ranges.
        Do not infer absent names from the identity store or add missing proof
        records. Any semantic record rewrite needs a separate checked plan.
        """
        self._deadline()
        before = validate_denial(
            qname,
            qtype,
            kind,
            evidence,
            keys.original,
            now=now,
            budget=self.budget,
            wildcard=wildcard,
        )
        transformed = []
        for records, signatures in evidence:
            changed = copy.deepcopy(records)
            result = self.signatures(records, changed, signatures, keys, now=now)
            transformed.append((changed, result.signatures))
        result_evidence = tuple(transformed)
        after = validate_denial(
            qname,
            qtype,
            kind,
            result_evidence,
            keys.synthetic,
            now=now,
            budget=self.budget,
            wildcard=wildcard,
        )
        if (before.valid, before.opt_out, before.closest_encloser, before.limitation) != (
            after.valid,
            after.opt_out,
            after.closest_encloser,
            after.limitation,
        ):
            raise DNSSECUnrepresentable("denial outcome changed during substitution")
        self._deadline()
        return DenialSubstitution(result_evidence, before, after)
