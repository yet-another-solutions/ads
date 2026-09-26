"""Shared trust-material validation; no HTTP, orchestration, mounts or secret persistence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID

CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----"
)
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def read_file(directory: Path, name: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    """Fixed leaf names, no symlink-following or unbounded clone content reads."""
    if name in (".", "..") or Path(name).name != name or maximum <= 0:
        raise ValueError("invalid CA material leaf or limit")
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent
        )
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("invalid CA material file")
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError("CA material exceeds limit")
    return content


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class Manifest:
    attempt: UUID
    fingerprint: str
    not_after: datetime


def manifest(directory: Path, role: str, attempt: UUID) -> Manifest:
    data = json.loads(read_file(directory, "complete.json", 4096), object_pairs_hook=_object)
    if (
        not isinstance(data, dict)
        or set(data) != {"format", "role", "attempt", "sha256", "not_after"}
        or type(data["format"]) is not int
        or data["format"] != 1
        or data["role"] != role
        or data["attempt"] != str(attempt)
        or not isinstance(data["sha256"], str)
        or re.fullmatch("[0-9a-f]{64}", data["sha256"]) is None
        or not isinstance(data["not_after"], str)
    ):
        raise ValueError("CA output manifest mismatch")
    expiry = datetime.fromisoformat(data["not_after"])
    if expiry.tzinfo is None or expiry.utcoffset() != UTC.utcoffset(None):
        raise ValueError("CA expiry must be UTC")
    return Manifest(attempt, data["sha256"], expiry)


def public_certificates(pem: bytes, *, optional: bool = False) -> list[x509.Certificate]:
    blocks = CERTIFICATE.findall(pem)
    if CERTIFICATE.sub(b"", pem).strip() or (not blocks and not optional):
        raise ValueError("expected public certificates only")
    return [x509.load_pem_x509_certificate(block) for block in blocks]


@dataclass(frozen=True, slots=True)
class PublicTrust:
    manifest: Manifest
    certificate: x509.Certificate
    pem: bytes
    signing_chain: tuple[x509.Certificate, ...]


def load_public(directory: Path, attempt: UUID) -> PublicTrust:
    """Validate the minted identity and complete signing hierarchy, never extra trust."""
    description = manifest(directory, "public", attempt)
    pem = read_file(directory, "trusted-egress-ca.pem", 65536)
    certificates = public_certificates(pem)
    if len(certificates) != 1:
        raise ValueError("expected only the minted egress certificate")
    certificate = certificates[0]
    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    if (
        not constraints.critical
        or not constraints.value.ca
        or constraints.value.path_length != 0
        or not usage.critical
        or not usage.value.key_cert_sign
        or not usage.value.crl_sign
        or certificate.not_valid_after_utc != description.not_after
        or not certificate.not_valid_before_utc <= datetime.now(UTC) < description.not_after
        or hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
        != description.fingerprint
    ):
        raise ValueError("minted CA certificate does not match its committed identity")
    chain = public_certificates(read_file(directory, "signing-chain.pem", 1048576))
    if (
        not 2 <= len(chain) <= 16
        or chain[0].not_valid_after_utc != description.not_after
        or len({item.public_bytes(serialization.Encoding.DER) for item in [certificate, *chain]})
        != len(chain) + 1
    ):
        raise ValueError("invalid signing hierarchy length, identity or expiry")
    certificate.verify_directly_issued_by(chain[0])
    now = datetime.now(UTC)
    for index, parent in enumerate(chain):
        constraints = parent.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = parent.extensions.get_extension_for_class(x509.KeyUsage)
        limit = constraints.value.path_length
        if (
            not constraints.critical
            or not constraints.value.ca
            or not usage.value.key_cert_sign
            or limit is not None
            and limit < index + 1
            or not parent.not_valid_before_utc <= now < parent.not_valid_after_utc
            or parent.not_valid_after_utc < description.not_after
            or any(
                extension.critical
                and extension.oid not in (ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE)
                or extension.oid in (ExtensionOID.NAME_CONSTRAINTS, ExtensionOID.EXTENDED_KEY_USAGE)
                for extension in parent.extensions
            )
        ):
            raise ValueError("invalid egress CA hierarchy")
        issuer = chain[index + 1] if index + 1 < len(chain) else parent
        parent.verify_directly_issued_by(issuer)
    complete = b"".join(
        item.public_bytes(serialization.Encoding.PEM) for item in [certificate, *chain]
    )
    return PublicTrust(description, certificate, complete, tuple(chain))


@dataclass(frozen=True, slots=True)
class EgressTrust:
    public: PublicTrust
    private_key: PrivateKey = field(repr=False)
    signing_chain: tuple[x509.Certificate, ...]
    additional_trust: tuple[x509.Certificate, ...]


def load_egress(public: Path, private: Path, attempt: UUID) -> EgressTrust:
    """Egress alone receives both separate RO clones and additional upstream anchors."""
    if public.resolve() == private.resolve():
        raise ValueError("public and private CA outputs must be separate")
    trusted = load_public(public, attempt)
    if manifest(private, "private", attempt) != trusted.manifest:
        raise ValueError("CA clone pair generations differ")
    key = serialization.load_pem_private_key(
        read_file(private, "trusted-egress-ca.key", 65536), password=None
    )
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError("unsupported egress CA key type")
    der, spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(der, spki) != trusted.certificate.public_key().public_bytes(
        der, spki
    ):
        raise ValueError("CA clone certificate/key mismatch")
    extra = public_certificates(read_file(public, "egress-only-trust.pem"), optional=True)
    for certificate in extra:
        if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("additional upstream trust must contain CA certificates")
    return EgressTrust(trusted, key, trusted.signing_chain, tuple(extra))
