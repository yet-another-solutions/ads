"""Bounded cryptographic evidence checks, NOT complete DNSSEC authentication.

Callers must establish anchor/delegation trust and negative/wildcard proofs
separately. A valid signature with an arbitrary supplied key is not a secure
answer. No AD/EDE flag, unsigned response, or absent cache entry supplies trust.
This layer retains successful alternatives and all observed failing paths;
local limitations never become claimed upstream cryptographic defects.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Literal

import dns.dnssec
import dns.dnssecalgs
import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.RRSIG
import dns.rrset

from ads_sandbox_egress.policy import RequestDenied

DNSKey = dns.rdtypes.ANY.DNSKEY.DNSKEY
DS = dns.rdtypes.ANY.DS.DS
RRSIG = dns.rdtypes.ANY.RRSIG.RRSIG
Defect = Literal[
    "signature_expired",
    "signature_not_yet_valid",
    "signature_invalid",
    "signature_missing",
    "signer_scope",
    "dnskey_missing",
    "dnskey_flags",
    "dnskey_protocol",
    "ds_mismatch",
]


@dataclass(frozen=True, slots=True)
class Failure:
    defect: Defect
    # Full fingerprints identify relationships, never just a short key tag.
    record: str | None = None
    key: str | None = None


@dataclass(frozen=True, slots=True)
class VerifiedSignature:
    signature: RRSIG
    key: DNSKey
    wildcard: bool


@dataclass(frozen=True, slots=True)
class SignatureCheck:
    verified: tuple[VerifiedSignature, ...]
    failures: tuple[Failure, ...]
    unsupported: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def valid(self) -> bool:
        """Cryptographic success only; trust and wildcard proof remain separate."""
        return bool(self.verified)


@dataclass(frozen=True, slots=True)
class DSCheck:
    # Cryptographic DS matches, not a statement that the supplied DS is trusted.
    matched: tuple[DNSKey, ...]
    failures: tuple[Failure, ...]
    unsupported: tuple[str, ...]
    supported_paths: int


@dataclass(slots=True)
class CryptoBudget:
    """One budget shared across the full resolution's cryptographic checks."""

    remaining: int = 128

    def consume(self, count: int = 1) -> None:
        if type(count) is not int or count < 1:
            raise ValueError("positive verification work required")
        if self.remaining < count:
            raise RequestDenied("dnssec_crypto_budget")
        self.remaining -= count


def fingerprint(record: DNSKey | DS | RRSIG) -> str:
    wire = record.to_wire()
    assert wire is not None
    return hashlib.sha256(wire).hexdigest()


def _bounded(rrset: dns.rrset.RRset, *, maximum: int = 128) -> None:
    if not rrset.name.is_absolute() or rrset.rdclass != dns.rdataclass.IN or len(rrset) > maximum:
        raise RequestDenied("dnssec_evidence_scope_or_limit")
    total = 0
    owner = rrset.name.to_wire()
    assert owner is not None
    for record in rrset:
        wire = record.to_wire()
        assert wire is not None
        total += len(owner) + len(wire) + 10
        if total > 65535:
            raise RequestDenied("dnssec_evidence_wire_limit")


def _algorithm_supported(algorithm: int) -> bool:
    try:
        # Registry includes algorithms the implementation can actually verify,
        # unlike the IANA identifier enum. Keep verification policy separate
        # from the narrower synthetic-key generation support set.
        dns.dnssecalgs.get_algorithm_cls(algorithm)
    except dns.exception.UnsupportedAlgorithm:
        return False
    probe = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, f"256 3 {algorithm} AA==")
    assert isinstance(probe, DNSKey)
    return dns.dnssec.default_policy.ok_to_validate(probe)


def check_signatures(
    records: dns.rrset.RRset,
    signatures: dns.rrset.RRset | None,
    keys: dns.rrset.RRset,
    *,
    now: float,
    budget: CryptoBudget,
) -> SignatureCheck:
    """Check an acquired RRset against the supplied zone's DNSKEY set.

    Missing signatures/keys describe this evidence, not an inference that
    signing was required. The trust-chain owner must establish that expectation.
    Iterate all candidate full keys, including colliding short key tags.
    """
    _bounded(records)
    _bounded(keys, maximum=64)
    if (
        not math.isfinite(now)
        or not 0 <= now < 2**32
        or not records
        or keys.rdtype != dns.rdatatype.DNSKEY
        or not records.name.is_subdomain(keys.name)
        or any(not isinstance(key, DNSKey) for key in keys)
    ):
        raise RequestDenied("dnssec_verification_inputs")
    if signatures is None or not signatures:
        return SignatureCheck((), (Failure("signature_missing"),), (), ())
    _bounded(signatures, maximum=64)
    if (
        signatures.name != records.name
        or signatures.rdtype != dns.rdatatype.RRSIG
        or signatures.covers != records.rdtype
        or any(not isinstance(sig, RRSIG) for sig in signatures)
    ):
        raise RequestDenied("dnssec_signature_scope")
    verified: list[VerifiedSignature] = []
    failures: list[Failure] = []
    unsupported: list[str] = []
    limitations: list[str] = []
    for sig in signatures:
        assert isinstance(sig, RRSIG)
        sig_id = fingerprint(sig)
        if sig.signer != keys.name or sig.labels > len(records.name.labels) - 1:
            failures.append(Failure("signer_scope", sig_id))
            continue
        if not _algorithm_supported(sig.algorithm):
            unsupported.append(sig_id)
            continue
        # dnspython uses ordinary timestamp comparisons. Do not call wrapped
        # serial intervals a cryptographic defect just because this adapter
        # cannot represent them faithfully with that verifier.
        if sig.expiration < sig.inception or sig.expiration - sig.inception >= 2**31:
            limitations.append(sig_id)
            continue
        if sig.expiration < now:
            failures.append(Failure("signature_expired", sig_id))
        if sig.inception > now:
            failures.append(Failure("signature_not_yet_valid", sig_id))
        candidates = [
            key
            for key in keys
            if isinstance(key, DNSKey)
            and key.algorithm == sig.algorithm
            and dns.dnssec.key_id(key) == sig.key_tag
        ]
        if not candidates:
            failures.append(Failure("dnskey_missing", sig_id))
            continue
        for key in candidates:
            key_id = fingerprint(key)
            eligible = True
            if not key.flags & 256:
                failures.append(Failure("dnskey_flags", sig_id, key_id))
                eligible = False
            if key.protocol != 3:
                failures.append(Failure("dnskey_protocol", sig_id, key_id))
                eligible = False
            if not eligible:
                continue
            budget.consume()
            # Verify the signed bytes inside the signature's own time interval
            # too: an expired signature may independently also be corrupt.
            # Nothing signed is modified and "now" never authenticates a key.
            crypto_time = max(sig.inception, min(now, sig.expiration))
            try:
                dns.dnssec.validate_rrsig(
                    records,
                    sig,
                    {keys.name: dns.rrset.from_rdata(keys.name, keys.ttl, key)},
                    now=crypto_time,
                )
            except dns.exception.UnsupportedAlgorithm:
                limitations.append(sig_id)
            except (dns.exception.ValidationFailure, ValueError):
                failures.append(Failure("signature_invalid", sig_id, key_id))
            else:
                if sig.inception <= now <= sig.expiration:
                    owner_labels = len(records.name.labels) - 1
                    expanded = sig.labels < owner_labels and not (
                        records.name.labels[0] == b"*" and sig.labels == owner_labels - 1
                    )
                    verified.append(VerifiedSignature(sig, key, expanded))
    return SignatureCheck(tuple(verified), tuple(failures), tuple(unsupported), tuple(limitations))


def check_ds(
    delegation: dns.rrset.RRset, keys: dns.rrset.RRset, *, budget: CryptoBudget
) -> DSCheck:
    """Compare positive parent DS evidence with a child DNSKEY set.

    The caller must authenticate DS in the parent and then validate the full
    child's DNSKEY RRset using a matched eligible key. An empty/missing DS set
    is NOT proof of an insecure delegation and is intentionally rejected here.
    """
    _bounded(delegation, maximum=64)
    _bounded(keys, maximum=64)
    if (
        not delegation
        or delegation.rdtype != dns.rdatatype.DS
        or keys.rdtype != dns.rdatatype.DNSKEY
        or delegation.name != keys.name
        or any(not isinstance(item, DS) for item in delegation)
        or any(not isinstance(item, DNSKey) for item in keys)
    ):
        raise RequestDenied("dnssec_delegation_inputs")
    matched: list[DNSKey] = []
    failures: list[Failure] = []
    unsupported: list[str] = []
    supported = 0
    for ds in delegation:
        assert isinstance(ds, DS)
        ds_id = fingerprint(ds)
        if (
            not _algorithm_supported(ds.algorithm)
            or ds.digest_type not in (1, 2, 4)
            or not dns.dnssec.default_policy.ok_to_validate_ds(ds.digest_type)
        ):
            unsupported.append(ds_id)
            continue
        supported += 1
        candidates = [
            key
            for key in keys
            if isinstance(key, DNSKey)
            and key.algorithm == ds.algorithm
            and dns.dnssec.key_id(key) == ds.key_tag
        ]
        if not candidates:
            failures.append(Failure("dnskey_missing", ds_id))
        for key in candidates:
            budget.consume()
            key_id = fingerprint(key)
            if not key.flags & 256:
                failures.append(Failure("dnskey_flags", ds_id, key_id))
            if key.protocol != 3:
                failures.append(Failure("dnskey_protocol", ds_id, key_id))
            if dns.dnssec.make_ds(keys.name, key, ds.digest_type, validating=True) != ds:
                failures.append(Failure("ds_mismatch", ds_id, key_id))
            elif key not in matched:
                # A digest match does not erase the separate eligibility defect.
                matched.append(key)
    return DSCheck(tuple(matched), tuple(failures), tuple(unsupported), supported)
