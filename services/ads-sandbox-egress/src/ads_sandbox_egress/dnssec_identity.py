"""Durable DNSSEC signing identities, not upstream authentication or a resolver.

Only the separately fenced runtime may initialize the sandbox root. Zone
boundaries and original DNSKEY material must come from acquired evidence; this
module does not infer cuts from suffixes or promote unsigned data to secure.
Mapped keys are prepared, not automatically published/activated.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.RRSIG
import dns.rrset
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from ads_sandbox_egress.identity_store import IdentityStore, StateUnavailable

PrivateKey = (
    rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
    | ed448.Ed448PrivateKey
)
DNSKey = dns.rdtypes.ANY.DNSKEY.DNSKEY
_ROOT = "dnssec/root-v1"


def _wire(value: dns.name.Name | DNSKey) -> bytes:
    result = value.to_wire()
    assert result is not None  # No output file supplied to dnspython.
    return result


class DNSSECUnrepresentable(Exception):
    """A construction limitation, never evidence of upstream cryptographic failure."""


def _zone(zone: dns.name.Name) -> dns.name.Name:
    if not zone.is_absolute():
        raise ValueError("absolute observed zone required")
    return zone.canonicalize()


def _generate(algorithm: int) -> PrivateKey:
    if algorithm in (8, 10):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algorithm == 13:
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == 14:
        return ec.generate_private_key(ec.SECP384R1())
    if algorithm == 15:
        return ed25519.Ed25519PrivateKey.generate()
    if algorithm == 16:
        return ed448.Ed448PrivateKey.generate()
    # Explicit component support set, NOT an upstream DNSSEC classification.
    # Legacy/other algorithms need a separate representability decision.
    raise DNSSECUnrepresentable("DNSSEC signing algorithm not implemented")


def _dnskey(private: PrivateKey, algorithm: int, flags: int, protocol: int) -> DNSKey:
    result = dns.dnssec.make_dnskey(private.public_key(), algorithm, flags=flags, protocol=protocol)
    if not isinstance(result, DNSKey):
        raise StateUnavailable("unexpected DNSKEY material")
    return result


@dataclass(frozen=True, slots=True)
class SigningIdentity:
    name: str
    zone: dns.name.Name
    dnskey: DNSKey
    private_key: PrivateKey = field(repr=False)
    stage: str

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(_wire(self.zone) + _wire(self.dnskey)).hexdigest()

    def key_rrset(self, ttl: int) -> dns.rrset.RRset:
        if type(ttl) is not int or not 0 <= ttl <= 2**31 - 1:
            raise ValueError("bounded DNSKEY TTL required")
        return dns.rrset.from_rdata(self.zone, ttl, self.dnskey)

    def sign(
        self,
        records: dns.rrset.RRset,
        *,
        inception: int,
        expiration: int,
    ) -> dns.rdtypes.ANY.RRSIG.RRSIG:
        if (
            records.rdclass != dns.rdataclass.IN
            or not records.name.is_absolute()
            or not records.name.is_subdomain(self.zone)
            or not 1 <= len(records) <= 128
            or type(inception) is not int
            or type(expiration) is not int
            or not 0 <= inception < expiration <= 2**32 - 1
        ):
            raise ValueError("explicit bounded signature and zone scope required")
        wire_size = 0
        for record in records:
            wire = record.to_wire()
            assert wire is not None
            wire_size += len(_wire(records.name)) + 10 + len(wire)
            if wire_size > 65535:
                raise ValueError("DNSSEC RRset wire budget exceeded")
        # Caller verifies the intended candidate outcome before publication.
        # Inception/expiration are explicit to support faithful defect crafting.
        return dns.dnssec.sign(
            records,
            self.private_key,
            self.zone,
            self.dnskey,
            inception=inception,
            expiration=expiration,
        )


class DNSSECIdentities:
    def __init__(self, store: IdentityStore) -> None:
        self.store = store

    def _read(
        self,
        name: str,
        zone: dns.name.Name,
        original: DNSKey | None,
        kind: str,
    ) -> SigningIdentity | None:
        stored = self.store.find_key(name)
        if stored is None:
            return None
        try:
            data = json.loads(stored[1])
            if (
                stored[0] != kind
                or set(data) != {"zone", "original", "dnskey"}
                or data["zone"] != _wire(zone).hex()
                or data["original"] != (_wire(original).hex() if original is not None else None)
            ):
                raise StateUnavailable("DNSSEC identity metadata mismatch")
            wire = bytes.fromhex(data["dnskey"])
            key = dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.DNSKEY, wire, 0, len(wire))
            private = serialization.load_der_private_key(stored[2], password=None)
            if not isinstance(key, DNSKey) or not isinstance(
                private,
                (
                    rsa.RSAPrivateKey,
                    ec.EllipticCurvePrivateKey,
                    ed25519.Ed25519PrivateKey,
                    ed448.Ed448PrivateKey,
                ),
            ):
                raise StateUnavailable("DNSSEC private key type")
            if _dnskey(private, key.algorithm, key.flags, key.protocol) != key:
                raise StateUnavailable("DNSSEC public/private mismatch")
            if original is not None and (key.algorithm, key.flags, key.protocol) != (
                original.algorithm,
                original.flags,
                original.protocol,
            ):
                raise StateUnavailable("DNSSEC original key parameters changed")
            return SigningIdentity(name, zone, key, private, stored[3])
        except StateUnavailable:
            raise
        except Exception:
            raise StateUnavailable("invalid retained DNSSEC identity") from None

    def _prepare(
        self,
        name: str,
        zone: dns.name.Name,
        original: DNSKey | None,
        kind: str,
    ) -> SigningIdentity:
        private = _generate(original.algorithm if original is not None else 15)
        key = _dnskey(
            private,
            original.algorithm if original is not None else 15,
            original.flags if original is not None else 257,
            original.protocol if original is not None else 3,
        )
        metadata = json.dumps(
            {
                "zone": _wire(zone).hex(),
                "original": _wire(original).hex() if original is not None else None,
                "dnskey": _wire(key).hex(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.store.prepare_key(
            name,
            kind,
            metadata,
            private.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        return SigningIdentity(name, zone, key, private, "prepared")

    def initialize_root(self) -> SigningIdentity:
        """Explicit initial custody operation. Never used as recovery fallback."""
        zone = dns.name.root
        if self.store.find_key(_ROOT) is not None:
            raise StateUnavailable("DNSSEC root already exists")
        return self._prepare(_ROOT, zone, None, "root")

    def root(self, *, expected_fingerprint: str) -> SigningIdentity:
        identity = self._read(_ROOT, dns.name.root, None, "root")
        if identity is None or identity.fingerprint != expected_fingerprint:
            raise StateUnavailable("required DNSSEC root missing or mismatched")
        return identity

    def mapped(
        self, zone: dns.name.Name, original: DNSKey, *, generation: int = 1
    ) -> SigningIdentity:
        zone = _zone(zone)
        if (
            not isinstance(original, DNSKey)
            or type(generation) is not int
            or not 1 <= generation <= 2**31 - 1
        ):
            raise ValueError("full upstream DNSKEY and explicit generation required")
        # Full wire identity includes flags/protocol/algorithm and key bytes.
        name = (
            "dnssec/"
            + hashlib.sha256(_wire(zone)).hexdigest()
            + "/"
            + hashlib.sha256(_wire(original)).hexdigest()
            + "/"
            + str(generation)
        )
        found = self._read(name, zone, original, "dnssec")
        return found if found is not None else self._prepare(name, zone, original, "dnssec")

    def observed(self, zone: dns.name.Name, original: DNSKey) -> SigningIdentity:
        """A fresh acquired key may start a new generation, never revive a tombstone."""
        zone = _zone(zone)
        prefix = (
            "dnssec/"
            + hashlib.sha256(_wire(zone)).hexdigest()
            + "/"
            + hashlib.sha256(_wire(original)).hexdigest()
            + "/"
        )
        generations = [
            int(name.removeprefix(prefix))
            for name in self.store.key_names("dnssec")
            if name.startswith(prefix)
        ]
        generation = max(generations, default=1)
        if generations and self.store.key_stage(prefix + str(generation)) == "retired":
            generation += 1
        return self.mapped(zone, original, generation=generation)

    def recover(self, name: str) -> SigningIdentity:
        """Recover a journal dependency with its full stored original identity."""
        try:
            kind, public, _, _ = self.store.key(name)
            data = json.loads(public)
            if kind != "dnssec":
                raise ValueError("not a mapped key")
            zone = dns.name.from_wire(bytes.fromhex(data["zone"]), 0)[0]
            wire = bytes.fromhex(data["original"])
            original = dns.rdata.from_wire(
                dns.rdataclass.IN, dns.rdatatype.DNSKEY, wire, 0, len(wire)
            )
            if not isinstance(original, DNSKey):
                raise ValueError("not DNSKEY")
            expected = (
                "dnssec/"
                + hashlib.sha256(_wire(zone)).hexdigest()
                + "/"
                + hashlib.sha256(_wire(original)).hexdigest()
                + "/"
            )
            if not name.startswith(expected) or not name.removeprefix(expected).isdigit():
                raise ValueError("mapping identity mismatch")
            found = self._read(name, zone, original, "dnssec")
            if found is None:
                raise ValueError("missing mapping")
            return found
        except (ValueError, KeyError, TypeError):
            raise StateUnavailable("invalid DNSSEC lifecycle dependency") from None
