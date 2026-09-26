"""Compose and recheck certificate-bound OCSP evidence before frontend TLS.

Public status responses are never reused across different certificate serials
or issuers. Certificate pairs remain stable; status generations are fresh and
retain their acquired validity intervals. Missing status remains missing,
including on Must-Staple certificates.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from ads_sandbox_egress.certificate_mirror import CertificateMirror, Issued
from ads_sandbox_egress.certificates import (
    CertificateDefectRequiresMirror,
    CertificatePairs,
    PairDestination,
    certificate_builder,
)
from ads_sandbox_egress.ocsp_der import preserve_fields
from ads_sandbox_egress.ocsp_status import inspect_status
from ads_sandbox_egress.origin_tls import OriginCertificate
from ads_sandbox_egress.tls_transport import FrontendIdentity


def substitute_status(
    wire: bytes | None,
    source: x509.Certificate,
    source_issuer: x509.Certificate,
    candidate: x509.Certificate,
    issuer: x509.Certificate,
    private: ec.EllipticCurvePrivateKey,
    *,
    now: datetime,
) -> bytes | None:
    before = inspect_status(wire, source, source_issuer, now=now)
    if wire is None:
        return None
    response, single = before.response, before.single
    if before.defects == {"responder_failure"}:
        assert response is not None
        return response.public_bytes(Encoding.DER)
    supported = {
        "revoked",
        "unknown",
        "expired",
        "future",
        "signature",
        "critical_extension",
        "freshness_unknown",
        "revocation_time",
        "responder_authority",
        "responder_time",
        "certificate_binding",
    }
    binding_failure = before.defects == {"certificate_binding"}
    if binding_failure and response is not None:
        values = tuple(response.responses)
        single = values[0] if values else None
    if response is None or single is None or before.defects - supported:
        raise CertificateDefectRequiresMirror("OCSP_condition_requires_composer")
    signing_certificate, signing_key = issuer, private
    extras = []
    if before.defects & {"responder_authority", "responder_time"}:
        candidates = [
            item
            for item in response.certificates
            if (
                response.responder_name == item.subject
                or response.responder_key_hash
                == x509.SubjectKeyIdentifier.from_public_key(item.public_key()).digest
            )
        ]
        if len(candidates) != 1:
            raise CertificateDefectRequiresMirror("OCSP_delegated_identity_ambiguous")
        delegated = candidates[0]
        signing_key = ec.generate_private_key(ec.SECP384R1())
        signed = certificate_builder(
            delegated,
            signing_key,
            issuer,
            "http://status.invalid/unused",
            cap_expiry=False,
            bind_issuer_certificate=True,
        ).sign(private, hashes.SHA384())
        try:
            delegated.verify_directly_issued_by(source_issuer)
        except (ValueError, InvalidSignature):
            # Preserve unissued responder authority, not just absent EKU.
            from ads_sandbox_egress.certificate_mirror import _damaged

            signed = _damaged(signed)
        signing_certificate = signed
        extras = [signed]
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            candidate,
            issuer,
            single.hash_algorithm,
            single.certificate_status,
            single.this_update_utc,
            single.next_update_utc,
            single.revocation_time_utc,
            single.revocation_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, signing_certificate)
    )
    if extras:
        builder = builder.certificates(extras)
    for extension in response.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    result = builder.sign(signing_key, hashes.SHA256()).public_bytes(Encoding.DER)
    try:
        result = preserve_fields(
            result,
            wire,
            signing_key,
            wrong_serial=(1 if candidate.serial_number != 1 else 2) if binding_failure else None,
            invalid_signature="signature" in before.defects,
            source_index=before.index,
        )
    except (ValueError, IndexError):
        raise CertificateDefectRequiresMirror("OCSP_envelope_unrepresentable") from None
    after = inspect_status(result, candidate, issuer, now=now)
    if before.defects != after.defects or (
        not binding_failure
        and (after.single is None or single.certificate_status != after.single.certificate_status)
    ):
        raise CertificateDefectRequiresMirror("OCSP_substitution_outcome_changed")
    return result


class CertificateStatusComposer:
    def __init__(self, pairs: CertificatePairs, mirror: CertificateMirror) -> None:
        self.pairs, self.mirror = pairs, mirror

    def compose(
        self, destination: PairDestination, observed: OriginCertificate
    ) -> FrontendIdentity:
        if (
            not observed.verified
            or observed.revoked
            or any(value is not None for value in observed.staples[1:])
        ):
            chain = tuple(x509.load_der_x509_certificate(value) for value in observed.built_chain)

            def statuses(issued: Issued) -> tuple[bytes | None, ...]:
                result: list[bytes | None] = []
                for depth in range(max(issued) + 1):
                    wire = observed.staples[depth] if depth < len(observed.staples) else None
                    if wire is None:
                        result.append(None)
                        continue
                    if depth + 1 >= len(chain):
                        raise CertificateDefectRequiresMirror("OCSP_issuer_requires_composer")
                    issuer, private, candidate = issued[depth]
                    result.append(
                        substitute_status(
                            wire,
                            chain[depth],
                            chain[depth + 1],
                            candidate,
                            issuer,
                            private,
                            now=datetime.now(UTC),
                        )
                    )
                return tuple(result)

            return self.mirror.for_status_composition(destination, observed, statuses)
        candidate = self.pairs.for_status_composition(destination, observed)
        if not observed.staples:
            return candidate  # Missing stays missing; TLS_FEATURE is not removed.
        chain = tuple(x509.load_der_x509_certificate(value) for value in observed.built_chain)
        if len(chain) < 2:
            raise CertificateDefectRequiresMirror("OCSP_issuer_requires_composer")
        leaf = x509.load_pem_x509_certificate(candidate.certificate_chain[0])
        wire = substitute_status(
            observed.staples[0],
            chain[0],
            chain[1],
            leaf,
            self.pairs.signer.certificate,
            self.pairs.signer.private_key,
            now=datetime.now(UTC),
        )
        return replace(candidate, staples=(wire,) if wire is not None else ())
