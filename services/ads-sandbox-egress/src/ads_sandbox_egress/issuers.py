from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass(frozen=True, slots=True)
class UntrustedIssuer:
    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey = field(repr=False)


def untrusted_issuer(parent_not_after: datetime) -> UntrustedIssuer:
    """Call exactly once at egress process bootstrap; never serialize either result.

    This independent self-signed issuer is not signed by the trusted hierarchy,
    persisted in the DNSSEC/ECH store, or included in sandbox/upstream trust.
    """
    now = datetime.now(UTC)
    if (
        parent_not_after.tzinfo is None
        or parent_not_after.utcoffset() != UTC.utcoffset(None)
        or parent_not_after <= now
        or parent_not_after.microsecond
    ):
        raise ValueError("untrusted issuer needs the live intermediate's exact UTC expiry")
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ADS Untrusted Egress CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(parent_not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA384())
    )
    return UntrustedIssuer(certificate, key)
