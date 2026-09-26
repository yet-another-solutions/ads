"""Verify candidate synthetic outcomes before publishing them to a TLS client.

Trust is the mounted egress CA and signing hierarchy, not egress-only origin trust
and never the independent process-local untrusted issuer. Continuing the native
verification callback collects defects; it does not convert them into success.
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

from cryptography.hazmat.primitives.serialization import Encoding

from ads_commons.egress_trust import public_certificates
from ads_sandbox_egress.origin_tls import VerificationIssue, _certificate_der, compatibility_issues
from ads_sandbox_egress.policy import canonical_host
from ads_sandbox_egress.tls import TLSFailure, TLSLibrary


class CertificateValidator:
    def __init__(self, library: TLSLibrary, anchor: bytes, *, partial_chain: bool = False) -> None:
        if not 1 <= len(anchor) <= 1048576:
            raise ValueError("explicit egress trust bundle required")
        anchors = public_certificates(anchor)
        if not 1 <= len(anchors) <= 17:
            raise ValueError("invalid egress trust bundle length")
        self.partial_chain = partial_chain
        self.library, self.anchor = library, anchor

    def observe(
        self,
        chain: tuple[bytes, ...],
        name: str,
        *,
        crls: tuple[bytes, ...] = (),
        check_revocation: bool = False,
    ) -> tuple[VerificationIssue, ...]:
        if (
            not chain
            or len(chain) > 16
            or sum(map(len, chain)) > 131072
            or len(crls) > 16
            or sum(map(len, crls)) > 4194304
        ):
            raise TLSFailure("candidate_validation_limit")
        name = canonical_host(name)
        library = self.library
        ffi, crypto = library.ffi, library.crypto
        certificates: list[Any] = []
        native_crls: list[Any] = []
        store = context = untrusted = ffi.NULL
        issues: list[VerificationIssue] = []
        seen = failed = False

        def certificate(pem: bytes) -> Any:
            bio = crypto.BIO_new_mem_buf(pem, len(pem))
            library.require(bio, "bio_allocation")
            try:
                result = crypto.PEM_read_bio_X509(bio, ffi.NULL, ffi.NULL, ffi.NULL)
                library.require(result, "candidate_certificate_decode")
                certificates.append(result)
                return result
            finally:
                crypto.BIO_free(bio)

        @ffi.callback("int(int, X509_STORE_CTX *)", error=0)
        def verified(preverified: int, verification: Any) -> int:
            nonlocal seen, failed
            try:
                seen = True
                if not preverified:
                    code = crypto.X509_STORE_CTX_get_error(verification)
                    depth = crypto.X509_STORE_CTX_get_error_depth(verification)
                    current = crypto.X509_STORE_CTX_get_current_cert(verification)
                    if len(issues) >= 64 or code == 0 or not 0 <= depth <= 16:
                        raise TLSFailure("candidate_validation_limit")
                    issue = VerificationIssue(
                        code, depth, hashlib.sha256(_certificate_der(library, current)).hexdigest()
                    )
                    if issue not in issues:
                        issues.append(issue)
                return 1
            except Exception:
                failed = True
                return 0

        try:
            store = crypto.X509_STORE_new()
            context = crypto.X509_STORE_CTX_new()
            untrusted = crypto.OPENSSL_sk_new_null()
            for handle in (store, context, untrusted):
                library.require(handle, "candidate_verifier_allocation")
            # Public trust loader owns hierarchy/identity checks. This verifier
            # uses exactly that explicit bundle, never ambient upstream trust.
            for item in public_certificates(self.anchor):
                anchor = certificate(item.public_bytes(Encoding.PEM))
                library.require(crypto.X509_STORE_add_cert(store, anchor), "candidate_anchor")
            leaf = certificate(chain[0])
            for pem in chain[1:]:
                library.require(
                    crypto.OPENSSL_sk_push(untrusted, certificate(pem)), "candidate_chain"
                )
            for pem in crls:
                bio = crypto.BIO_new_mem_buf(pem, len(pem))
                library.require(bio, "bio_allocation")
                try:
                    crl = crypto.PEM_read_bio_X509_CRL(bio, ffi.NULL, ffi.NULL, ffi.NULL)
                    library.require(crl, "candidate_crl_decode")
                    native_crls.append(crl)
                    library.require(crypto.X509_STORE_add_crl(store, crl), "candidate_crl")
                finally:
                    crypto.BIO_free(bio)
            library.require(
                crypto.X509_STORE_CTX_init(context, store, leaf, untrusted),
                "candidate_verifier_init",
            )
            parameter = crypto.X509_STORE_CTX_get0_param(context)
            library.require(parameter, "candidate_verify_parameter")
            # Default reaches the configured root. Partial-chain mode is explicit
            # for compatibility regression only, not the production trust model.
            flags = 0x20 | 0x8000
            if self.partial_chain:
                flags |= 0x80000
            if check_revocation:
                flags |= 0x4 | 0x8
            library.require(crypto.X509_VERIFY_PARAM_set_flags(parameter, flags), "candidate_flags")
            library.require(crypto.X509_VERIFY_PARAM_set_purpose(parameter, 2), "candidate_purpose")
            try:
                ipaddress.ip_address(name)
            except ValueError:
                encoded = name.encode("ascii")
                library.require(
                    crypto.X509_VERIFY_PARAM_set1_host(parameter, encoded, len(encoded)),
                    "candidate_hostname",
                )
            else:
                library.require(
                    crypto.X509_VERIFY_PARAM_set1_ip_asc(parameter, name.encode("ascii")),
                    "candidate_ip_identity",
                )
            crypto.X509_STORE_CTX_set_verify_cb(context, verified)
            if crypto.X509_verify_cert(context) != 1 or not seen or failed:
                raise TLSFailure("candidate_verification_failed")
            built = crypto.X509_STORE_CTX_get0_chain(context)
            count = crypto.OPENSSL_sk_num(built)
            if not 1 <= count <= 16:
                raise TLSFailure("candidate_chain_limit")
            built_der = tuple(
                _certificate_der(library, ffi.cast("X509 *", crypto.OPENSSL_sk_value(built, index)))
                for index in range(count)
            )
            for issue in compatibility_issues(built_der):
                if issue not in issues:
                    issues.append(issue)
            if len(issues) > 64:
                raise TLSFailure("candidate_validation_limit")
            return tuple(issues)
        finally:
            crypto.X509_STORE_CTX_free(context)
            crypto.X509_STORE_free(store)
            crypto.OPENSSL_sk_free(untrusted)
            for pointer in certificates:
                crypto.X509_free(pointer)
            for pointer in native_crls:
                crypto.X509_CRL_free(pointer)
