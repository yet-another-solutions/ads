from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----"
)


def certificates(pem: bytes, *, optional: bool = False) -> list[x509.Certificate]:
    """Accept certificates only, not keys, comments or unparsed trailing material."""
    if len(pem) > 4 * 1024 * 1024:
        raise ValueError("certificate bundle exceeds limit")
    blocks = CERTIFICATE.findall(pem)
    if CERTIFICATE.sub(b"", pem).strip() or (not blocks and not optional):
        raise ValueError("expected a certificate-only PEM bundle")
    return [x509.load_pem_x509_certificate(block) for block in blocks]


def _ca(cert: x509.Certificate, now: datetime, *, subordinate_levels: int) -> None:
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    if not constraints.critical or not constraints.value.ca or not usage.value.key_cert_sign:
        raise ValueError("signer must have critical CA constraints and signing key usage")
    limit = constraints.value.path_length
    if limit is not None and limit < subordinate_levels:
        raise ValueError("signer path length does not permit the egress CA")
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError("CA is not currently valid")
    public_key = cert.public_key()
    if not (
        isinstance(public_key, rsa.RSAPublicKey)
        and public_key.key_size >= 2048
        or isinstance(public_key, ec.EllipticCurvePublicKey)
        and public_key.key_size >= 256
    ):
        raise ValueError("unsupported or weak CA public key")
    algorithm = cert.signature_hash_algorithm
    if algorithm is None or algorithm.name not in ("sha256", "sha384", "sha512"):
        raise ValueError("unsupported or weak CA signature")
    # Do not silently discard constraints that require a constrained issuer/runtime.
    allowed = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE}
    if any(extension.critical and extension.oid not in allowed for extension in cert.extensions):
        raise ValueError("unsupported critical CA extension")
    if any(
        extension.oid in (ExtensionOID.NAME_CONSTRAINTS, ExtensionOID.EXTENDED_KEY_USAGE)
        for extension in cert.extensions
    ):
        raise ValueError("constrained signing hierarchies require explicit runtime support")


@dataclass(frozen=True, slots=True)
class Material:
    certificate: bytes
    chain: bytes
    additional_trust: bytes
    private_key: bytes = field(repr=False)
    fingerprint: str
    not_after: str


def mint(chain_pem: bytes, key_pem: bytes, additional_pem: bytes = b"") -> Material:
    """Validate the configured hierarchy and mint one subordinate, never a parent key copy."""
    now = datetime.now(UTC)
    chain = certificates(chain_pem)
    if len(chain) < 2:
        raise ValueError("a root-backed signing intermediate chain is required")
    for index, cert in enumerate(chain):
        _ca(cert, now, subordinate_levels=index + 1)
        issuer = chain[index + 1] if index + 1 < len(chain) else cert
        cert.verify_directly_issued_by(issuer)
        if cert.not_valid_after_utc < chain[0].not_valid_after_utc:
            raise ValueError("ancestor expires before the configured intermediate")
    parent = chain[0]
    if parent.issuer == parent.subject:
        raise ValueError("input signer must be an intermediate, not the root")
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError("unsupported intermediate key type")
    encoding, form = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(encoding, form) != parent.public_key().public_bytes(
        encoding, form
    ):
        raise ValueError("intermediate certificate and private key do not match")
    extra = certificates(additional_pem, optional=True)
    for cert in extra:
        _ca(cert, now, subordinate_levels=0)
    # The shared trusted signing key is created here only. The unrelated untrusted
    # issuer is process-owned by egress and is intentionally absent from this artifact.
    child_key = ec.generate_private_key(ec.SECP384R1())
    child = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ADS Trusted Egress CA")]))
        .issuer_name(parent.subject)
        .public_key(child_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(max(parent.not_valid_before_utc, now - timedelta(minutes=5)))
        .not_valid_after(parent.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(child_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA384())
    )
    child.verify_directly_issued_by(parent)
    pem = serialization.Encoding.PEM
    return Material(
        certificate=child.public_bytes(pem),
        chain=b"".join(cert.public_bytes(pem) for cert in chain),
        additional_trust=b"".join(cert.public_bytes(pem) for cert in extra),
        private_key=child_key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        fingerprint=child.fingerprint(hashes.SHA256()).hex(),
        not_after=child.not_valid_after_utc.isoformat(),
    )
