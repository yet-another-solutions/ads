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


def _defects(check: SignatureCheck | DSCheck) -> tuple[str, ...]:
    # Counts retain failures across colliding candidate paths. Fingerprints
    # necessarily change during substitution and are not outcome categories.
    return tuple(sorted(failure.defect for failure in check.failures))


def _corrupt(value: bytes) -> bytes:
    if not value:
        raise DNSSECUnrepresentable("empty cryptographic value")
    return bytes((value[0] ^ 1,)) + value[1:]


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
            mapped.append(self.identities.mapped(original.name, key))
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
            if len(candidates) != 1 or signature.signer != keys.original.name:
                # Missing keys and ambiguous tag-collision paths require a
                # separate structural construction, not invented key material.
                raise DNSSECUnrepresentable("missing or ambiguous signature key")
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
            if len(candidates) != 1:
                raise DNSSECUnrepresentable("missing or ambiguous delegation key")
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
