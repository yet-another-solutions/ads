"""Real origin TLS observation, with explicit verification outcomes.

The verifier continues solely to acquire the origin chain on the SAME TLS
connection for defect mirroring. This never turns a defective peer into a
trusted peer. No HTTP bytes may be sent until the owning two-leg coordinator
has constructed the required client-visible outcome and authorized a request.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import math
import threading
from dataclasses import dataclass
from typing import Any, Literal

from cryptography import x509

from ads_sandbox_egress.http1 import reset
from ads_sandbox_egress.policy import canonical_host
from ads_sandbox_egress.tls import (
    TLSFailure,
    TLSLibrary,
    TLSSession,
    UnmappableReason,
    UnmappableTLS,
)
from ads_sandbox_egress.tls_transport import TLSStream


@dataclass(frozen=True, slots=True)
class VerificationIssue:
    code: int
    depth: int
    certificate_sha256: str


def compatibility_issues(chain: tuple[bytes, ...]) -> tuple[VerificationIssue, ...]:
    """Retain OpenSSL 3 strict CA criticality across OpenSSL 4's relaxed profile.

    Applied only to the native BUILT chain, never unrelated presented extras.
    A mirrored noncritical CA can still be accepted by a permissive client;
    strict clients must see the original defect rather than a repaired chain.
    """
    if not 1 <= len(chain) <= 16 or sum(map(len, chain)) > 131072:
        raise TLSFailure("compatibility_chain_limit")
    result = []
    for depth, der in enumerate(chain):
        certificate = x509.load_der_x509_certificate(der)
        try:
            constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            continue
        if constraints.value.ca and not constraints.critical:
            result.append(VerificationIssue(89, depth, hashlib.sha256(der).hexdigest()))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class OriginCertificate:
    presented_chain: tuple[bytes, ...]
    built_chain: tuple[bytes, ...]
    issues: tuple[VerificationIssue, ...]
    selected_alpn: bytes | None
    staples: tuple[bytes | None, ...] = ()
    revoked: tuple[int, ...] = ()

    @property
    def verified(self) -> bool:
        return not self.issues and not self.revoked


def _certificate_der(library: TLSLibrary, certificate: Any) -> bytes:
    if certificate == library.ffi.NULL:
        raise TLSFailure("origin_certificate_absent")
    size = library.crypto.i2d_X509(certificate, library.ffi.NULL)
    if not 1 <= size <= 65536:
        raise TLSFailure("origin_certificate_limit")
    buffer = library.ffi.new("unsigned char[]", size)
    pointer = library.ffi.new("unsigned char **", buffer)
    if library.crypto.i2d_X509(certificate, pointer) != size:
        raise TLSFailure("origin_certificate_encoding")
    return bytes(library.ffi.buffer(buffer, size))


class OriginContext:
    """Egress-only trust. Never install these anchors into the sandbox."""

    def __init__(
        self,
        library: TLSLibrary,
        *,
        extra_trust: tuple[bytes, ...] = (),
        system_trust: bool = True,
        crls: tuple[bytes, ...] = (),
        check_revocation: bool = False,
    ) -> None:
        self.library = library
        self._owner = threading.get_ident()
        self._closed = False
        self._sessions: dict[Any, TLSSession] = {}
        if (
            len(extra_trust) > 128
            or sum(map(len, extra_trust)) > 1048576
            or len(crls) > 128
            or sum(map(len, crls)) > 4194304
        ):
            raise TLSFailure("origin_trust_limit")
        ffi, ssl, crypto = library.ffi, library.ssl, library.crypto
        self._context = ssl.SSL_CTX_new(ssl.TLS_client_method())
        library.require(self._context, "origin_context_allocation")
        try:
            if system_trust:
                library.require(ssl.SSL_CTX_set_default_verify_paths(self._context), "origin_trust")
            trust = ssl.SSL_CTX_get_cert_store(self._context)
            library.require(trust, "origin_trust_store")
            for pem in extra_trust:
                bio = crypto.BIO_new_mem_buf(pem, len(pem))
                library.require(bio, "bio_allocation")
                certificate = ffi.NULL
                try:
                    certificate = crypto.PEM_read_bio_X509(bio, ffi.NULL, ffi.NULL, ffi.NULL)
                    library.require(certificate, "origin_trust_decode")
                    library.require(crypto.X509_STORE_add_cert(trust, certificate), "origin_trust")
                finally:
                    crypto.X509_free(certificate)
                    crypto.BIO_free(bio)
            for pem in crls:
                bio = crypto.BIO_new_mem_buf(pem, len(pem))
                library.require(bio, "bio_allocation")
                crl = ffi.NULL
                try:
                    crl = crypto.PEM_read_bio_X509_CRL(bio, ffi.NULL, ffi.NULL, ffi.NULL)
                    library.require(crl, "origin_crl_decode")
                    library.require(crypto.X509_STORE_add_crl(trust, crl), "origin_crl")
                finally:
                    crypto.X509_CRL_free(crl)
                    crypto.BIO_free(bio)
            if check_revocation:
                # Missing/expired CRLs remain explicit issues, not "good".
                library.require(crypto.X509_STORE_set_flags(trust, 0x4 | 0x8), "origin_crl_check")
            library.require(ssl.SSL_CTX_ctrl(self._context, 123, 0x0303, ffi.NULL), "tls_minimum")
            ssl.SSL_CTX_ctrl(self._context, 51, 65536, ffi.NULL)
            ssl.SSL_CTX_ctrl(self._context, 44, 0, ffi.NULL)
            ssl.SSL_CTX_set_options(self._context, (1 << 14) | (1 << 30))
            ssl.SSL_CTX_set_verify_depth(self._context, 15)
            self._verify_callback = ffi.callback(
                "int(int, X509_STORE_CTX *)", self._verify, error=0
            )
            ssl.SSL_CTX_set_verify(self._context, 1, self._verify_callback)
        except BaseException:
            self.close()
            raise

    def _check_thread(self) -> None:
        if self._owner != threading.get_ident():
            raise TLSFailure("tls_thread_ownership")

    def _verify(self, preverified: int, verification: Any) -> int:
        try:
            self._check_thread()
            library = self.library
            pointer = library.crypto.X509_STORE_CTX_get_ex_data(
                verification, library.ssl.SSL_get_ex_data_X509_STORE_CTX_idx()
            )
            session = self._sessions[library.ffi.cast("SSL *", pointer)]
            if not isinstance(session, OriginSession):
                return 0
            if not preverified:
                code = library.crypto.X509_STORE_CTX_get_error(verification)
                depth = library.crypto.X509_STORE_CTX_get_error_depth(verification)
                certificate = library.crypto.X509_STORE_CTX_get_current_cert(verification)
                if len(session.issues) >= 64 or not 0 <= depth <= 15 or code == 0:
                    return 0
                issue = VerificationIssue(
                    code, depth, hashlib.sha256(_certificate_der(library, certificate)).hexdigest()
                )
                if issue not in session.issues:
                    session.issues.append(issue)
            session.verification_seen = True
            return 1  # Observe, not authorize or relabel as trusted.
        except Exception:
            return 0

    def session(self, name: str, protocols: tuple[bytes, ...]) -> OriginSession:
        self._check_thread()
        if self._closed:
            raise TLSFailure("closed_origin_context")
        return OriginSession(self, name, protocols)

    def close(self) -> None:
        self._check_thread()
        if not self._closed:
            self._closed = True
            self.library.ssl.SSL_CTX_free(self._context)


class OriginSession(TLSSession):
    """Reuse memory-BIO ownership/I/O, not the frontend handshake or resume."""

    def __init__(self, context: OriginContext, name: str, protocols: tuple[bytes, ...]) -> None:
        super().__init__(context)
        self.issues: list[VerificationIssue] = []
        self.verification_seen = False
        self.certificate: OriginCertificate | None = None
        self.protocols = protocols
        try:
            self.name = canonical_host(name)
            ffi, ssl, crypto = self.library.ffi, self.library.ssl, self.library.crypto
            self.library.require(ssl.SSL_ctrl(self._ssl, 65, 1, ffi.NULL), "origin_status_request")
            parameter = ssl.SSL_get0_param(self._ssl)
            self.library.require(parameter, "origin_verify_parameter")
            # STRICT plus TRUSTED_FIRST; no partial-chain or weak-signature
            # exception is enabled to make a failed peer look valid.
            self.library.require(
                crypto.X509_VERIFY_PARAM_set_flags(parameter, 0x20 | 0x8000), "origin_verify_flags"
            )
            try:
                ipaddress.ip_address(self.name)
            except ValueError:
                encoded = self.name.encode("ascii")
                self.library.require(
                    crypto.X509_VERIFY_PARAM_set1_host(parameter, encoded, len(encoded)),
                    "origin_hostname",
                )
                sni = ffi.new("char[]", encoded)
                self.library.require(ssl.SSL_ctrl(self._ssl, 55, 0, sni), "origin_sni")
            else:
                self.library.require(
                    crypto.X509_VERIFY_PARAM_set1_ip_asc(parameter, self.name.encode("ascii")),
                    "origin_ip_identity",
                )
            if any(not 1 <= len(protocol) <= 255 for protocol in protocols):
                raise TLSFailure("origin_alpn_offer")
            wire = b"".join(bytes([len(protocol)]) + protocol for protocol in protocols)
            if len(wire) > 65533:
                raise TLSFailure("origin_alpn_limit")
            if wire and ssl.SSL_set_alpn_protos(self._ssl, wire, len(wire)) != 0:
                raise TLSFailure("origin_alpn_offer")
        except BaseException:
            self.close()
            raise

    def _chain(self, chain: Any) -> tuple[bytes, ...]:
        library = self.library
        size = library.crypto.OPENSSL_sk_num(chain)
        if not 1 <= size <= 16:
            raise TLSFailure("origin_chain_limit")
        result = tuple(
            _certificate_der(
                library, library.ffi.cast("X509 *", library.crypto.OPENSSL_sk_value(chain, i))
            )
            for i in range(size)
        )
        if sum(map(len, result)) > 65536:
            raise TLSFailure("origin_chain_limit")
        return result

    def handshake(self) -> Literal["read", "write", "complete"]:
        self._check()
        if self.established:
            return "complete"
        library = self.library
        library.crypto.ERR_clear_error()
        error = self._result(library.ssl.SSL_connect(self._ssl))
        if error == 2:
            return "read"
        if error == 3:
            return "write"
        if error != 0 or not self.verification_seen:
            raise TLSFailure("origin_verification_absent")
        out, size = library.ffi.new("const unsigned char **"), library.ffi.new("unsigned int *")
        library.ssl.SSL_get0_alpn_selected(self._ssl, out, size)
        selected = bytes(library.ffi.buffer(out[0], size[0])) if size[0] else None
        if selected is not None and selected not in self.protocols:
            raise TLSFailure("unoffered_origin_alpn")
        self.selected = selected
        built = self._chain(library.ssl.SSL_get0_verified_chain(self._ssl))
        for issue in compatibility_issues(built):
            if issue not in self.issues:
                self.issues.append(issue)
        if len(self.issues) > 64:
            raise TLSFailure("origin_validation_limit")
        from ads_sandbox_egress.tls_status import acquire_staples

        self.certificate = OriginCertificate(
            self._chain(library.ssl.SSL_get_peer_cert_chain(self._ssl)),
            built,
            tuple(self.issues),
            selected,
            acquire_staples(self.library, self._ssl),
        )
        self.established = True
        return "complete"

    def resume(
        self,
        certificate_chain: tuple[bytes, ...],
        private_key: bytes,
        alpn: bytes | None,
        staples: tuple[bytes | None, ...] = (),
    ) -> None:
        raise TLSFailure("origin_cannot_install_client_credentials")


async def inspect_origin(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    context: OriginContext,
    name: str,
    protocols: tuple[bytes, ...],
    *,
    handshake_timeout: float = 10,
) -> tuple[TLSStream, OriginCertificate]:
    """Use an already destination-authorized, separately originated socket."""
    session = None
    try:
        if not math.isfinite(handshake_timeout) or handshake_timeout <= 0:
            raise ValueError("finite positive origin deadline required")
        session = context.session(name, protocols)
        stream = TLSStream(reader, writer, session, idle_timeout=30)
        try:
            async with asyncio.timeout(handshake_timeout):
                while True:
                    state = session.handshake()
                    await stream.drain()
                    if state == "complete":
                        if session.certificate is None:
                            raise TLSFailure("origin_certificate_absent")
                        return stream, session.certificate
                    if state != "read":
                        raise TLSFailure("unexpected_memory_bio_backpressure")
                    await stream._receive()
        except (TLSFailure, OSError):
            # Only actual origin handshake/I/O failures reach this outcome.
            # Local invalid settings or closed contexts above are not relabeled
            # as an upstream certificate defect. Never retain arbitrary text.
            raise UnmappableTLS(UnmappableReason.UPSTREAM_HANDSHAKE) from None
    except BaseException:
        if session is not None:
            session.close()
        reset(writer)
        raise
