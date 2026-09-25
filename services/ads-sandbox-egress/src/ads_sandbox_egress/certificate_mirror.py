"""Compose and independently check client-visible defects, never clean them.

This owns non-revocation certificate construction. CRL/status acquisition and
publication are separate obligations. An unsupported composer path raises the
explicit incomplete-support error, NOT the approved genuinely-unmappable reset
classification. Process-local untrusted issuer keys are never persisted here.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID

from ads_sandbox_egress.certificate_validation import CertificateValidator
from ads_sandbox_egress.certificates import (
    CertificateDefectRequiresMirror,
    EgressSigner,
    PairDestination,
    _new_leaf_key,
    certificate_builder,
    validate_crl_url,
)
from ads_sandbox_egress.issuers import UntrustedIssuer
from ads_sandbox_egress.origin_tls import OriginCertificate, VerificationIssue
from ads_sandbox_egress.tls import UnmappableReason, UnmappableTLS
from ads_sandbox_egress.tls_transport import FrontendIdentity

_PEM = serialization.Encoding.PEM
_DER = serialization.Encoding.DER
_ISSUER = frozenset((18, 19, 20, 21))
_SUPPORTED = frozenset((7, 9, 10, 26, 34, 62, 64)) | _ISSUER


def _outcomes(issues: tuple[VerificationIssue, ...]) -> frozenset[tuple[int, int]]:
    # A self-signed leaf may become a leaf under our explicitly untrusted
    # process-local root. Both represent unknown trust, not a repaired chain.
    return frozenset(
        (18, -1)
        if issue.code in (18, 19)
        else (20, -1)
        if issue.code in (20, 21)
        else (issue.code, issue.depth)
        for issue in issues
    )


class CertificateMirror:
    def __init__(
        self,
        signer: EgressSigner,
        untrusted: UntrustedIssuer,
        validator: CertificateValidator,
        crl_url: str,
    ) -> None:
        validate_crl_url(crl_url)
        if untrusted.certificate.not_valid_after_utc != signer.certificate.not_valid_after_utc:
            raise ValueError("process issuer expiry must equal minted CA expiry")
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        untrusted_public = untrusted.certificate.public_key().public_bytes(_DER, spki)
        if untrusted_public == signer.certificate.public_key().public_bytes(_DER, spki):
            raise ValueError("process issuer must be independent")
        if untrusted_public != untrusted.private_key.public_key().public_bytes(_DER, spki):
            raise ValueError("process issuer key mismatch")
        untrusted.certificate.verify_directly_issued_by(untrusted.certificate)
        self.signer, self.untrusted, self.validator = signer, untrusted, validator
        self.crl_url = crl_url

    def mirror(self, destination: PairDestination, observed: OriginCertificate) -> FrontendIdentity:
        self.signer.require_current()
        if observed.verified:
            raise ValueError("successful origins require their stable certificate pair")
        if (
            not 1 <= len(observed.built_chain) <= 16
            or not observed.presented_chain
            or observed.presented_chain[0] != observed.built_chain[0]
            or sum(map(len, observed.built_chain)) > 65536
            or len(observed.issues) > 64
        ):
            raise UnmappableTLS(UnmappableReason.MALFORMED_CERTIFICATE)
        try:
            source = tuple(x509.load_der_x509_certificate(der) for der in observed.built_chain)
        except ValueError:
            raise UnmappableTLS(UnmappableReason.MALFORMED_CERTIFICATE) from None
        defects: dict[int, set[int]] = defaultdict(set)
        for issue in observed.issues:
            if (
                not 0 <= issue.depth < len(source)
                or issue.certificate_sha256
                != hashlib.sha256(observed.built_chain[issue.depth]).hexdigest()
            ):
                raise UnmappableTLS(UnmappableReason.UNREPRESENTABLE_VALIDATION)
            if issue.code not in _SUPPORTED:
                raise CertificateDefectRequiresMirror("certificate_condition_not_implemented")
            defects[issue.depth].add(issue.code)
        # Do not strip a stapled-status obligation while mirroring another error.
        if any(
            extension.oid == ExtensionOID.TLS_FEATURE
            for certificate in source
            for extension in certificate.extensions
        ):
            raise CertificateDefectRequiresMirror("stapled_status_requires_composer")
        unknown = any(issue.code in _ISSUER for issue in observed.issues)
        if unknown:
            issuer, issuer_key = self.untrusted.certificate, self.untrusted.private_key
            tail = [issuer.public_bytes(_PEM)]
        else:
            issuer, issuer_key = self.signer.certificate, self.signer.private_key
            tail = [issuer.public_bytes(_PEM)] + [
                certificate.public_bytes(_PEM) for certificate in self.signer.chain
            ]
        incomplete = unknown and any(issue.code in (20, 21) for issue in observed.issues)
        if incomplete:
            # Deliberately absent synthetic issuer: do not turn an incomplete
            # upstream path into a complete chain under a different unknown root.
            missing_key = ec.generate_private_key(ec.SECP384R1())
            missing = certificate_builder(
                issuer,
                missing_key,
                issuer,
                self.crl_url,
                cap_expiry=False,
                bind_issuer_certificate=True,
            ).sign(issuer_key, hashes.SHA384())
            issuer, issuer_key = missing, missing_key
        # Only reproduce the portion needed to carry the observed defects.
        # Self-issued (NOT self-signed) bridges retain path_length=0 on the
        # minted CA without introducing an unrelated path-length failure.
        maximum = max(defects)
        for depth in range(maximum, 0, -1):
            key = ec.generate_private_key(ec.SECP384R1())
            builder = certificate_builder(
                source[depth],
                key,
                issuer,
                self.crl_url,
                subject=issuer.subject,
                cap_expiry=False,
                bind_issuer_certificate=True,
            )
            signing_key = (
                ec.generate_private_key(ec.SECP384R1()) if 7 in defects[depth] else issuer_key
            )
            bridge = builder.sign(signing_key, hashes.SHA384())
            tail.insert(0, bridge.public_bytes(_PEM))
            issuer, issuer_key = bridge, key
        leaf_key = _new_leaf_key(source[0])
        builder = certificate_builder(
            source[0],
            leaf_key,
            issuer,
            self.crl_url,
            cap_expiry=False,
            bind_issuer_certificate=True,
        )
        signing_key = ec.generate_private_key(ec.SECP384R1()) if 7 in defects[0] else issuer_key
        leaf = builder.sign(signing_key, hashes.SHA384())
        chain = (leaf.public_bytes(_PEM), *tail)
        actual = self.validator.observe(chain, destination.server_name or str(destination.address))
        if _outcomes(actual) != _outcomes(observed.issues):
            raise CertificateDefectRequiresMirror("synthetic_validation_outcome_mismatch")
        return FrontendIdentity(
            chain,
            leaf_key.private_bytes(
                _PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
            observed.selected_alpn,
        )
