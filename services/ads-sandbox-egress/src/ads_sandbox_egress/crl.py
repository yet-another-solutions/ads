"""Durable issuer-wide local CRLs, not upstream status acquisition.

Only explicitly supplied egress-owned authorities can sign here. Parent CA
CRLs remain separate public inputs; no parent private key is acquired/copied.
HTTP serving reads authenticated committed generations, never unpublished bytes.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ads_sandbox_egress.identity_store import IdentityStore, StateUnavailable

_DER, _PEM = serialization.Encoding.DER, serialization.Encoding.PEM


class CRLUnavailable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class CRLAuthority:
    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey = field(repr=False)

    def __post_init__(self) -> None:
        public = self.certificate.public_key()
        if (
            not isinstance(public, ec.EllipticCurvePublicKey)
            or public.public_numbers() != self.private_key.public_key().public_numbers()
            or not self.certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value.ca
            or not self.certificate.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign
        ):
            raise ValueError("invalid local CRL authority")

    @property
    def identity(self) -> str:
        return self.certificate.fingerprint(hashes.SHA256()).hex()


@dataclass(frozen=True, slots=True)
class PublishedCRL:
    issuer: str
    number: int
    certificate: x509.Certificate
    crl: x509.CertificateRevocationList
    der: bytes


def _clock(now: datetime) -> datetime:
    if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(None):
        raise ValueError("UTC CRL clock required")
    return now.replace(microsecond=0)


class CRLRepository:
    def __init__(self, store: IdentityStore, *, lifetime_seconds: int = 300) -> None:
        if type(lifetime_seconds) is not int or not 60 <= lifetime_seconds <= 3600:
            raise ValueError("bounded CRL lifetime required")
        self.store, self.lifetime_seconds = store, lifetime_seconds

    def _head(self, identity: str) -> PublishedCRL | None:
        head = self.store.crl_head(identity)
        if head is None:
            return None
        number, data, retain_until = head
        try:
            record = json.loads(data)
            if not isinstance(record, dict) or set(record) != {"issuer", "der"}:
                raise ValueError("invalid CRL record")
            cert = x509.load_pem_x509_certificate(record["issuer"].encode("ascii"))
            der = base64.b64decode(record["der"], validate=True)
            crl = x509.load_der_x509_crl(der)
            public = cert.public_key()
            next_update = crl.next_update_utc
            if (
                cert.fingerprint(hashes.SHA256()).hex() != identity
                or not isinstance(public, ec.EllipticCurvePublicKey)
                or not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or not cert.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign
                or crl.issuer != cert.subject
                or not crl.is_signature_valid(public)
                or crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number != number
                or next_update is None
                or next_update.timestamp() != retain_until
                or not crl.last_update_utc < next_update <= cert.not_valid_after_utc
                or len(crl) > 10000
                or len({entry.serial_number for entry in crl}) != len(crl)
            ):
                raise ValueError("invalid retained CRL")
            return PublishedCRL(identity, number, cert, crl, der)
        except (ValueError, TypeError, AttributeError, KeyError, x509.ExtensionNotFound):
            raise StateUnavailable("invalid authenticated CRL publication") from None

    def get(self, identity: str, *, now: datetime) -> PublishedCRL:
        now = _clock(now)
        result = self._head(identity)
        if result is None:
            raise CRLUnavailable("unknown_crl")
        expiry = result.crl.next_update_utc
        if (
            expiry is None
            or not result.certificate.not_valid_before_utc
            <= now
            < result.certificate.not_valid_after_utc
            or not result.crl.last_update_utc <= now < expiry
        ):
            raise CRLUnavailable("crl_not_current")
        return result

    def publish(
        self,
        authority: CRLAuthority,
        *,
        now: datetime,
        revoke: x509.Certificate | None = None,
    ) -> PublishedCRL:
        now = _clock(now)
        cert = authority.certificate
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise CRLUnavailable("crl_authority_not_current")
        previous = self._head(authority.identity)
        if previous is not None and now < previous.crl.last_update_utc:
            raise CRLUnavailable("crl_clock_rollback")
        if revoke is not None:
            try:
                revoke.verify_directly_issued_by(cert)
            except (ValueError, InvalidSignature):
                raise ValueError(
                    "revocation target must be issued by this local authority"
                ) from None
        revoked = (
            {entry.serial_number: entry for entry in previous.crl} if previous is not None else {}
        )
        new_revocation = revoke is not None and revoke.serial_number not in revoked
        if (
            previous is not None
            and not new_revocation
            and previous.crl.next_update_utc is not None
            and (previous.crl.next_update_utc - now).total_seconds() > self.lifetime_seconds / 2
        ):
            return self.get(authority.identity, now=now)
        if new_revocation:
            assert revoke is not None
            if len(revoked) >= 10000:
                raise CRLUnavailable("crl_entry_limit")
            revoked[revoke.serial_number] = (
                x509.RevokedCertificateBuilder()
                .serial_number(revoke.serial_number)
                .revocation_date(now)
                .build()
            )
        number = previous.number + 1 if previous is not None else 1
        expiry = min(now + timedelta(seconds=self.lifetime_seconds), cert.not_valid_after_utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(cert.subject)
            .last_update(now)
            .next_update(expiry)
            .add_extension(x509.CRLNumber(number), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    authority.private_key.public_key()
                ),
                False,
            )
        )
        for serial in sorted(revoked):
            builder = builder.add_revoked_certificate(revoked[serial])
        crl = builder.sign(authority.private_key, hashes.SHA384())
        content = json.dumps(
            {
                "issuer": cert.public_bytes(_PEM).decode("ascii"),
                "der": base64.b64encode(crl.public_bytes(_DER)).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        # Public evidence only; authority private keys never enter this record.
        self.store.prune_crls(authority.identity, now=now.timestamp())
        self.store.commit_crl(authority.identity, number - 1, content, expiry.timestamp())
        self.store.prune_crls(authority.identity, now=now.timestamp())
        return self.get(authority.identity, now=now)
