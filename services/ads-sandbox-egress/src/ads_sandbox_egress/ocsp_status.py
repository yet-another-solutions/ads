"""Bounded independent OCSP evidence classification, separate from chain trust.

Missing/unavailable status is never 'good'. The issuer is selected from the
observed built certificate chain, not from URLs or responder-provided roots.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, SignatureAlgorithmOID

from ads_sandbox_egress.ocsp_der import single_critical
from ads_sandbox_egress.ocsp_signature import pss_parameters


@dataclass(frozen=True, slots=True)
class StatusEvidence:
    response: ocsp.OCSPResponse | None
    single: ocsp.OCSPSingleResponse | None
    defects: frozenset[str]
    index: int = 0

    @property
    def good(self) -> bool:
        return (
            not self.defects
            and self.single is not None
            and (self.single.certificate_status == ocsp.OCSPCertStatus.GOOD)
        )


def _signature(response: ocsp.OCSPResponse, signer: x509.Certificate) -> None:
    key = signer.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        if response.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
            scheme, pss_digest = pss_parameters(response.public_bytes(serialization.Encoding.DER))
            key.verify(response.signature, response.tbs_response_bytes, scheme, pss_digest)
            return
        digest = response.signature_hash_algorithm
        if digest is None:
            raise UnsupportedAlgorithm("OCSP signature digest unavailable")
        if response.signature_algorithm_oid.dotted_string not in {
            "1.2.840.113549.1.1.5",
            "1.2.840.113549.1.1.11",
            "1.2.840.113549.1.1.12",
            "1.2.840.113549.1.1.13",
            "1.2.840.113549.1.1.14",
        }:
            raise UnsupportedAlgorithm("OCSP signer algorithm mismatch")
        key.verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(), digest)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        digest = response.signature_hash_algorithm
        if digest is None:
            raise UnsupportedAlgorithm("OCSP signature digest unavailable")
        if response.signature_algorithm_oid.dotted_string not in {
            "1.2.840.10045.4.1",
            "1.2.840.10045.4.3.1",
            "1.2.840.10045.4.3.2",
            "1.2.840.10045.4.3.3",
            "1.2.840.10045.4.3.4",
        }:
            raise UnsupportedAlgorithm("OCSP signer algorithm mismatch")
        key.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(digest))
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key.verify(response.signature, response.tbs_response_bytes)
    else:
        raise UnsupportedAlgorithm("OCSP signer algorithm unsupported")


def inspect_status(
    wire: bytes | None,
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    *,
    now: datetime,
) -> StatusEvidence:
    if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(None):
        raise ValueError("explicit UTC status clock required")
    if wire is None:
        return StatusEvidence(None, None, frozenset({"missing"}))
    if not 1 <= len(wire) <= 65536:
        return StatusEvidence(None, None, frozenset({"malformed"}))
    try:
        response = ocsp.load_der_ocsp_response(wire)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return StatusEvidence(response, None, frozenset({"responder_failure"}))
        singles = tuple(response.responses)
        if len(singles) > 16 or len(response.certificates) > 16:
            return StatusEvidence(response, None, frozenset({"capacity"}))
        defects = set()
        selected = []
        for index, single in enumerate(singles):
            request = (
                ocsp.OCSPRequestBuilder()
                .add_certificate(certificate, issuer, single.hash_algorithm)
                .build()
            )
            if (
                single.serial_number == certificate.serial_number
                and single.issuer_name_hash == request.issuer_name_hash
                and single.issuer_key_hash == request.issuer_key_hash
            ):
                selected.append((index, single))
        if len(selected) != 1:
            return StatusEvidence(response, None, frozenset({"certificate_binding"}))
        index, single = selected[0]
        candidates: list[x509.Certificate] = []
        for signer in (issuer, *response.certificates):
            identifier = x509.SubjectKeyIdentifier.from_public_key(signer.public_key()).digest
            if (
                response.responder_name is not None
                and response.responder_name == signer.subject
                or response.responder_key_hash is not None
                and response.responder_key_hash == identifier
            ):
                if all(signer != prior for prior in candidates):
                    candidates.append(signer)
        if len(candidates) != 1:
            return StatusEvidence(response, single, frozenset({"responder_identity"}))
        signer = candidates[0]
        if signer != issuer:
            try:
                signer.verify_directly_issued_by(issuer)
                understood = (
                    x509.BasicConstraints,
                    x509.KeyUsage,
                    x509.ExtendedKeyUsage,
                    x509.SubjectKeyIdentifier,
                    x509.AuthorityKeyIdentifier,
                    x509.OCSPNoCheck,
                )
                if any(
                    extension.critical and not isinstance(extension.value, understood)
                    for extension in signer.extensions
                ):
                    defects.add("responder_authority")
                eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
                    defects.add("responder_authority")
                try:
                    usage = signer.extensions.get_extension_for_class(x509.KeyUsage).value
                    if not usage.digital_signature:
                        defects.add("responder_authority")
                except x509.ExtensionNotFound:
                    pass
                if not signer.not_valid_before_utc <= now <= signer.not_valid_after_utc:
                    defects.add("responder_time")
            except (ValueError, InvalidSignature, x509.ExtensionNotFound):
                defects.add("responder_authority")
        try:
            _signature(response, signer)
        except InvalidSignature:
            defects.add("signature")
        if response.produced_at_utc > now or single.this_update_utc > now:
            defects.add("future")
        if single.next_update_utc is None:
            defects.add("freshness_unknown")
        elif single.next_update_utc < now or single.next_update_utc < single.this_update_utc:
            defects.add("expired")
        if any(extension.critical for extension in response.extensions):
            defects.add("critical_extension")
        if single_critical(wire, index):
            defects.add("critical_extension")
        if single.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            defects.add("revoked")
            if single.revocation_time_utc is None or single.revocation_time_utc > now:
                defects.add("revocation_time")
        elif single.certificate_status == ocsp.OCSPCertStatus.UNKNOWN:
            defects.add("unknown")
        return StatusEvidence(response, single, frozenset(defects), index)
    except UnsupportedAlgorithm:
        return StatusEvidence(None, None, frozenset({"unsupported"}))
    except (ValueError, TypeError, IndexError):
        return StatusEvidence(None, None, frozenset({"malformed"}))
