"""Encrypted stable SUCCESS pairs, separate from certificate-defect mirroring.

An origin observation is never a cached trust verdict. Every call checks the
current observation before looking up its pair. Defective origins must go to
the dedicated mirror path; this class never upgrades them to a clean identity.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from ads_sandbox_egress.identity_store import IdentityStore, StateUnavailable
from ads_sandbox_egress.origin_tls import OriginCertificate
from ads_sandbox_egress.policy import canonical_host
from ads_sandbox_egress.tls import TLSFailure
from ads_sandbox_egress.tls_transport import FrontendIdentity

LeafKey = (
    rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
    | ed448.Ed448PrivateKey
)
_PEM = serialization.Encoding.PEM
_DER = serialization.Encoding.DER
_SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


class CertificateDefectRequiresMirror(TLSFailure):
    """Supported defects cannot be handled by the clean-pair cache."""


@dataclass(frozen=True, slots=True)
class PairDestination:
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int
    server_name: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            raise ValueError("literal original destination required")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("invalid original port")
        if self.server_name is not None and canonical_host(self.server_name) != self.server_name:
            raise ValueError("canonical TLS name required")

    def fingerprint(self) -> str:
        return hashlib.sha256(
            json.dumps(
                (str(self.address), self.port, self.server_name),
                separators=(",", ":"),
            ).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class EgressSigner:
    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey = field(repr=False)
    chain: tuple[x509.Certificate, ...] = ()

    @classmethod
    def load(
        cls, certificate: bytes, private_key: bytes, chain: tuple[bytes, ...] = ()
    ) -> EgressSigner:
        if (
            len(certificate) > 65536
            or len(private_key) > 65536
            or len(chain) > 16
            or sum(map(len, chain)) > 131072
        ):
            raise TLSFailure("signer_input_limit")
        try:
            cert = x509.load_pem_x509_certificate(certificate)
            key = serialization.load_pem_private_key(private_key, password=None)
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if (
                not isinstance(key, ec.EllipticCurvePrivateKey)
                or not isinstance(key.curve, ec.SECP384R1)
                or not constraints.critical
                or not constraints.value.ca
                or constraints.value.path_length != 0
                or not usage.value.key_cert_sign
                or not usage.value.crl_sign
                or cert.public_key().public_bytes(_DER, _SPKI)
                != key.public_key().public_bytes(_DER, _SPKI)
            ):
                raise TLSFailure("invalid_minted_signer")
            result = cls(cert, key, tuple(x509.load_pem_x509_certificate(pem) for pem in chain))
            result.require_current()
            hierarchy = (cert,) + result.chain
            now = datetime.now(UTC)
            for position, current in enumerate(hierarchy):
                issuer = hierarchy[position + 1] if position + 1 < len(hierarchy) else current
                current.verify_directly_issued_by(issuer)
                basic = issuer.extensions.get_extension_for_class(x509.BasicConstraints)
                signing = issuer.extensions.get_extension_for_class(x509.KeyUsage)
                subordinate_levels = sum(
                    child.subject != child.issuer for child in hierarchy[: position + 1]
                )
                if (
                    not basic.critical
                    or not basic.value.ca
                    or not signing.value.key_cert_sign
                    or not issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc
                    or issuer.not_valid_after_utc < cert.not_valid_after_utc
                    or (
                        basic.value.path_length is not None
                        and basic.value.path_length < subordinate_levels
                    )
                ):
                    raise TLSFailure("invalid_minted_hierarchy")
            if result.chain and cert.not_valid_after_utc != result.chain[0].not_valid_after_utc:
                raise TLSFailure("minted_expiry_changed")
            return result
        except (
            ValueError,
            TypeError,
            x509.ExtensionNotFound,
            InvalidSignature,
            UnsupportedAlgorithm,
        ):
            raise TLSFailure("invalid_minted_signer") from None

    def require_current(self) -> None:
        now = datetime.now(UTC)
        if not self.certificate.not_valid_before_utc <= now <= self.certificate.not_valid_after_utc:
            raise TLSFailure("minted_signer_not_current")

    @property
    def fingerprint(self) -> str:
        return self.certificate.fingerprint(hashes.SHA256()).hex()


def _new_leaf_key(source: x509.Certificate) -> LeafKey:
    public = source.public_key()
    if isinstance(public, rsa.RSAPublicKey) and 2048 <= public.key_size <= 4096:
        return rsa.generate_private_key(public_exponent=65537, key_size=public.key_size)
    if isinstance(public, ec.EllipticCurvePublicKey):
        return ec.generate_private_key(public.curve)
    if isinstance(public, ed25519.Ed25519PublicKey):
        return ed25519.Ed25519PrivateKey.generate()
    if isinstance(public, ed448.Ed448PublicKey):
        return ed448.Ed448PrivateKey.generate()
    raise TLSFailure("unsupported_substitution_key")


def certificate_builder(
    source: x509.Certificate,
    key: LeafKey,
    issuer: x509.Certificate,
    crl_url: str,
    *,
    subject: x509.Name | None = None,
    cap_expiry: bool = True,
    bind_issuer_certificate: bool = False,
) -> x509.CertificateBuilder:
    """Preserve subject/SAN/constraints. Replace issuer-bound locator material."""
    issuer_public_key = issuer.public_key()
    if not isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        raise TLSFailure("unsupported_minted_signer")
    builder = (
        x509.CertificateBuilder()
        .subject_name(source.subject if subject is None else subject)
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(source.not_valid_before_utc)
        .not_valid_after(
            min(source.not_valid_after_utc, issuer.not_valid_after_utc)
            if cap_expiry
            else source.not_valid_after_utc
        )
    )
    replaced = {
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        ExtensionOID.CRL_DISTRIBUTION_POINTS,
        ExtensionOID.FRESHEST_CRL,
        ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
        ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS,
    }
    for extension in source.extensions:
        if extension.oid not in replaced:
            builder = builder.add_extension(extension.value, extension.critical)
    return (
        builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            (
                x509.AuthorityKeyIdentifier(
                    key_identifier=x509.SubjectKeyIdentifier.from_public_key(
                        issuer_public_key
                    ).digest,
                    authority_cert_issuer=[x509.DirectoryName(issuer.issuer)],
                    authority_cert_serial_number=issuer.serial_number,
                )
                if bind_issuer_certificate
                else x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key)
            ),
            False,
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            False,
        )
    )


def validate_crl_url(crl_url: str) -> None:
    parsed = urlsplit(crl_url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or len(crl_url) > 1024
        or not crl_url.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in crl_url)
    ):
        raise ValueError("explicit local CRL distribution URL required")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid CRL distribution port")


class CertificatePairs:
    def __init__(self, store: IdentityStore, signer: EgressSigner, crl_url: str) -> None:
        validate_crl_url(crl_url)
        self.store, self.signer, self.crl_url = store, signer, crl_url

    def valid(self, destination: PairDestination, observed: OriginCertificate) -> FrontendIdentity:
        return self._valid(destination, observed, compose_status=False)

    def for_status_composition(
        self, destination: PairDestination, observed: OriginCertificate
    ) -> FrontendIdentity:
        """Unpublished candidate; caller must compose/check status before TLS."""
        return self._valid(destination, observed, compose_status=True)

    def _valid(
        self, destination: PairDestination, observed: OriginCertificate, *, compose_status: bool
    ) -> FrontendIdentity:
        self.signer.require_current()
        if not observed.verified:
            raise CertificateDefectRequiresMirror("origin_defect_requires_mirroring")
        if not compose_status and any(status is not None for status in observed.staples):
            raise CertificateDefectRequiresMirror("origin_status_requires_composer")
        try:
            source = x509.load_der_x509_certificate(observed.presented_chain[0])
            built = tuple(x509.load_der_x509_certificate(der) for der in observed.built_chain)
        except (ValueError, IndexError):
            raise TLSFailure("malformed_origin_certificate") from None
        now = datetime.now(UTC)
        if not built or built[0].public_bytes(_DER) != source.public_bytes(_DER):
            raise TLSFailure("inconsistent_origin_chain")
        if any(not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc for cert in built):
            raise CertificateDefectRequiresMirror("origin_time_requires_revalidation")
        # Stapled-status synthesis is not implemented by a successful-pair cache.
        # Its caller must acquire/check the status and use the appropriate
        # certificate/status composer rather than stripping Must-Staple.
        if not compose_status and any(
            extension.oid == ExtensionOID.TLS_FEATURE for extension in source.extensions
        ):
            raise CertificateDefectRequiresMirror("origin_status_requires_composer")
        name = (
            f"tls/{self.signer.fingerprint}/{destination.fingerprint()}/"
            + source.fingerprint(hashes.SHA256()).hex()
        )
        retained = self.store.find_key(name)
        if retained is None:
            private = _new_leaf_key(source)
            certificate = certificate_builder(
                source, private, self.signer.certificate, self.crl_url
            ).sign(self.signer.private_key, hashes.SHA384())
            self.store.prepare_key(
                name,
                "tls",
                certificate.public_bytes(_PEM),
                private.private_bytes(
                    _PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                ),
            )
            retained = self.store.key(name)
        kind, public, private_pem, stage = retained
        if kind != "tls" or stage not in ("prepared", "published", "active"):
            raise StateUnavailable("invalid retained certificate pair")
        try:
            certificate = x509.load_pem_x509_certificate(public)
            key = serialization.load_pem_private_key(private_pem, password=None)
            certificate.verify_directly_issued_by(self.signer.certificate)
            if key.public_key().public_bytes(_DER, _SPKI) != certificate.public_key().public_bytes(
                _DER, _SPKI
            ):
                raise StateUnavailable("retained certificate key mismatch")
            if certificate.subject != source.subject:
                raise StateUnavailable("retained certificate subject mismatch")
            source_san = next(
                (
                    extension
                    for extension in source.extensions
                    if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ),
                None,
            )
            retained_san = next(
                (
                    extension
                    for extension in certificate.extensions
                    if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ),
                None,
            )
            if source_san != retained_san:
                raise StateUnavailable("retained certificate name mismatch")
            distribution = certificate.extensions.get_extension_for_class(
                x509.CRLDistributionPoints
            ).value
            if len(distribution) != 1 or distribution[0].full_name != [
                x509.UniformResourceIdentifier(self.crl_url)
            ]:
                raise StateUnavailable("retained CRL locator changed")
            if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
                raise CertificateDefectRequiresMirror("retained_pair_time_requires_mirroring")
        except (
            ValueError,
            TypeError,
            InvalidSignature,
            UnsupportedAlgorithm,
            x509.ExtensionNotFound,
        ):
            raise StateUnavailable("invalid retained certificate material") from None
        # Complete interrupted publication without changing the retained key,
        # certificate or serial. Persist before presenting the certificate.
        if stage == "prepared":
            self.store.advance(name, "prepared", "published")
            stage = "published"
        if stage == "published":
            self.store.advance(name, "published", "active")
        chain = (public, self.signer.certificate.public_bytes(_PEM)) + tuple(
            certificate.public_bytes(_PEM) for certificate in self.signer.chain
        )
        return FrontendIdentity(chain, private_pem, observed.selected_alpn)
