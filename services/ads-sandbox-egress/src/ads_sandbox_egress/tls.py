"""Socket-independent, bounded TLS termination through the public OpenSSL ABI.

No native compilation, private cryptography/CPython pointers, or plaintext key
files. All methods run on the owning event-loop thread. The caller transports
encrypted bytes and must obtain the real origin result before ``resume``.
Completing TLS never authorizes an HTTP request.
"""

from __future__ import annotations

import base64
import re
import threading
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from cffi import FFI

from ads_sandbox_egress.identity_store import IdentityStore, StateUnavailable
from ads_sandbox_egress.policy import RequestDenied, canonical_host

_ABI = """
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_store_st X509_STORE;
typedef struct X509_crl_st X509_CRL;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;
typedef struct stack_st OPENSSL_STACK;
typedef struct ocsp_response_st OCSP_RESPONSE;
typedef struct ossl_echstore_st OSSL_ECHSTORE;
typedef struct { uint16_t kem_id; uint16_t kdf_id; uint16_t aead_id; } OSSL_HPKE_SUITE;
const char *OpenSSL_version(int);
const SSL_METHOD *TLS_server_method(void);
const SSL_METHOD *TLS_client_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *);
void SSL_CTX_free(SSL_CTX *);
long SSL_CTX_ctrl(SSL_CTX *, int, long, void *);
long SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void));
uint64_t SSL_CTX_set_options(SSL_CTX *, uint64_t);
int SSL_CTX_set_num_tickets(SSL_CTX *, size_t);
int SSL_CTX_set_max_early_data(SSL_CTX *, uint32_t);
SSL *SSL_new(SSL_CTX *);
void SSL_free(SSL *);
void SSL_set_bio(SSL *, BIO *, BIO *);
int SSL_accept(SSL *);
int SSL_connect(SSL *);
void SSL_CTX_set_verify(SSL_CTX *, int, int (*)(int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *, int);
int SSL_CTX_set_default_verify_paths(SSL_CTX *);
X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);
int X509_STORE_add_cert(X509_STORE *, X509 *);
X509_STORE *X509_STORE_new(void);
void X509_STORE_free(X509_STORE *);
X509_STORE_CTX *X509_STORE_CTX_new(void);
void X509_STORE_CTX_free(X509_STORE_CTX *);
int X509_STORE_CTX_init(X509_STORE_CTX *, X509_STORE *, X509 *, OPENSSL_STACK *);
void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *, int (*)(int, X509_STORE_CTX *));
X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(const X509_STORE_CTX *);
OPENSSL_STACK *X509_STORE_CTX_get0_chain(const X509_STORE_CTX *);
int X509_verify_cert(X509_STORE_CTX *);
int X509_STORE_add_crl(X509_STORE *, X509_CRL *);
int X509_STORE_set_flags(X509_STORE *, unsigned long);
int X509_STORE_CTX_get_error(const X509_STORE_CTX *);
int X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *);
X509 *X509_STORE_CTX_get_current_cert(const X509_STORE_CTX *);
void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *, int);
int SSL_get_ex_data_X509_STORE_CTX_idx(void);
X509_VERIFY_PARAM *SSL_get0_param(SSL *);
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *, const char *, size_t);
int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM *, const char *);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *, unsigned long);
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *, int);
int SSL_set_alpn_protos(SSL *, const unsigned char *, unsigned int);
OPENSSL_STACK *SSL_get_peer_cert_chain(const SSL *);
OPENSSL_STACK *SSL_get0_verified_chain(const SSL *);
int OPENSSL_sk_num(const OPENSSL_STACK *);
void *OPENSSL_sk_value(const OPENSSL_STACK *, int);
OPENSSL_STACK *OPENSSL_sk_new_null(void);
int OPENSSL_sk_push(OPENSSL_STACK *, const void *);
void OPENSSL_sk_free(OPENSSL_STACK *);
int i2d_X509(const X509 *, unsigned char **);
int i2d_OCSP_RESPONSE(const OCSP_RESPONSE *, unsigned char **);
OCSP_RESPONSE *d2i_OCSP_RESPONSE(OCSP_RESPONSE **, const unsigned char **, long);
void OCSP_RESPONSE_free(OCSP_RESPONSE *);
int SSL_get_error(const SSL *, int);
int SSL_use_certificate(SSL *, X509 *);
int SSL_use_PrivateKey(SSL *, EVP_PKEY *);
int SSL_check_private_key(const SSL *);
long SSL_ctrl(SSL *, int, long, void *);
void SSL_CTX_set_client_hello_cb(SSL_CTX *, int (*)(SSL *, int *, void *), void *);
int SSL_client_hello_get0_ext(SSL *, unsigned int, const unsigned char **, size_t *);
void SSL_CTX_set_alpn_select_cb(SSL_CTX *,
 int (*)(SSL *, const unsigned char **, unsigned char *,
          const unsigned char *, unsigned int, void *), void *);
void SSL_get0_alpn_selected(const SSL *, const unsigned char **, unsigned int *);
int SSL_ech_get1_status(SSL *, char **, char **);
OSSL_ECHSTORE *OSSL_ECHSTORE_new(void *, const char *);
void OSSL_ECHSTORE_free(OSSL_ECHSTORE *);
int OSSL_ECHSTORE_read_pem(OSSL_ECHSTORE *, BIO *, int);
int OSSL_ECHSTORE_new_config(OSSL_ECHSTORE *, uint16_t, uint16_t, const char *, OSSL_HPKE_SUITE);
int OSSL_ECHSTORE_write_pem(OSSL_ECHSTORE *, int, BIO *);
int OSSL_ECHSTORE_num_keys(const OSSL_ECHSTORE *, int *);
int SSL_CTX_set1_echstore(SSL_CTX *, OSSL_ECHSTORE *);
const BIO_METHOD *BIO_s_mem(void);
BIO *BIO_new(const BIO_METHOD *);
BIO *BIO_new_mem_buf(const void *, int);
int BIO_free(BIO *);
int BIO_read(BIO *, void *, int);
int BIO_write(BIO *, const void *, int);
size_t BIO_ctrl_pending(BIO *);
X509 *PEM_read_bio_X509(BIO *, X509 **, void *, void *);
X509_CRL *PEM_read_bio_X509_CRL(BIO *, X509_CRL **, void *, void *);
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *, EVP_PKEY **, void *, void *);
void X509_free(X509 *);
void X509_CRL_free(X509_CRL *);
void EVP_PKEY_free(EVP_PKEY *);
void CRYPTO_free(void *, const char *, int);
void ERR_clear_error(void);
int SSL_read_ex(SSL *, void *, size_t, size_t *);
int SSL_write_ex(SSL *, const void *, size_t, size_t *);
int SSL_shutdown(SSL *);
"""


class TLSFailure(Exception):
    """Internal, credential-free reason. The transport resets on failure."""


class UnmappableReason(StrEnum):
    UPSTREAM_HANDSHAKE = "upstream_handshake"
    MALFORMED_CERTIFICATE = "malformed_certificate"
    UNREPRESENTABLE_VALIDATION = "unrepresentable_validation"
    UNAVAILABLE_STATUS = "unavailable_status"


class UnmappableTLS(TLSFailure):
    """Approved reset-only outcome, never an alternative to a supported mirror."""

    def __init__(self, reason: UnmappableReason) -> None:
        if not isinstance(reason, UnmappableReason):
            raise ValueError("fixed unmappable TLS reason required")
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class ClientHello:
    server_name: str | None
    protocols: tuple[bytes, ...]
    ech_accepted: bool
    ech_present: bool
    outer_name: str | None


def parse_protocols(wire: bytes) -> tuple[bytes, ...]:
    result: list[bytes] = []
    offset = 0
    while offset < len(wire):
        size = wire[offset]
        offset += 1
        if not size or offset + size > len(wire):
            raise TLSFailure("invalid_alpn")
        result.append(wire[offset : offset + size])
        offset += size
    if not result:
        raise TLSFailure("empty_alpn")
    return tuple(result)


def parse_hello(
    sni: bytes | None,
    alpn: bytes | None,
    ech: bytes | None,
    status: int,
    outer: str | None,
) -> ClientHello:
    name = None
    if sni is not None:
        if (
            len(sni) < 6
            or int.from_bytes(sni[:2]) != len(sni) - 2
            or sni[2] != 0
            or int.from_bytes(sni[3:5]) != len(sni) - 5
        ):
            raise TLSFailure("invalid_sni")
        try:
            name = canonical_host(sni[5:].decode("ascii"))
        except (UnicodeError, RequestDenied) as exc:
            raise TLSFailure("invalid_sni") from exc
    protocols: tuple[bytes, ...] = ()
    if alpn is not None:
        if len(alpn) < 3 or int.from_bytes(alpn[:2]) != len(alpn) - 2:
            raise TLSFailure("invalid_alpn")
        protocols = parse_protocols(alpn[2:])
    # A plaintext ech_is_inner from an external peer is NOT accepted ECH.
    accepted = status == 1 and ech == b"\x01"
    if (status == 1) != (ech == b"\x01"):
        raise TLSFailure("inconsistent_ech")
    return ClientHello(name, protocols, accepted, ech is not None, outer)


@dataclass(frozen=True, slots=True)
class ECHKey:
    configuration: bytes
    private_pem: bytes = field(repr=False)

    @property
    def config_id(self) -> int:
        return self.configuration[6]

    @classmethod
    def from_pem(cls, pem: bytes) -> ECHKey:
        if not pem or len(pem) > 65536:
            raise TLSFailure("invalid_ech_key")
        matches = re.findall(
            rb"-----BEGIN ECHCONFIG-----\s+(.*?)-----END ECHCONFIG-----", pem, re.S
        )
        if len(matches) != 1:
            raise TLSFailure("invalid_ech_config")
        try:
            config = base64.b64decode(re.sub(rb"\s", b"", matches[0]), validate=True)
        except ValueError:
            raise TLSFailure("invalid_ech_config") from None
        if (
            len(config) < 8
            or int.from_bytes(config[:2]) != len(config) - 2
            or config[2:4] != b"\xfe\x0d"
            or int.from_bytes(config[4:6]) != len(config) - 6
        ):
            raise TLSFailure("invalid_ech_config")
        return cls(config, pem)

    def prepare(self, store: IdentityStore, name: str) -> None:
        store.prepare_key(name, "ech", self.configuration, self.private_pem)

    @classmethod
    def recover(cls, store: IdentityStore, name: str) -> ECHKey:
        kind, public, private, stage = store.key(name)
        if kind != "ech" or stage not in ("published", "active", "retiring"):
            raise StateUnavailable("ECH key is not available for serving")
        result = cls.from_pem(private)
        if result.configuration != public:
            raise StateUnavailable("ECH public/private mapping mismatch")
        return result


class TLSLibrary:
    """One pinned library pair, opened before the runtime binds any listener."""

    def __init__(self, directory: Path) -> None:
        self.ffi = FFI()
        self.ffi.cdef(_ABI)
        try:
            # These symbol tables are defined by _ABI, not by cffi's generic
            # Lib stub. Keep dynamic native handles inside this module.
            self.crypto: Any = cast(Any, self.ffi.dlopen(str(directory / "libcrypto.so.4")))
            self.ssl: Any = cast(Any, self.ffi.dlopen(str(directory / "libssl.so.4")))
            version = cast(bytes, self.ffi.string(self.crypto.OpenSSL_version(0))).decode("ascii")
            if not version.startswith("OpenSSL 4.0.2 "):
                raise TLSFailure("unsupported_openssl_version")
            # Resolve mandatory symbols now, not after accepting a connection.
            for name in (
                "SSL_CTX_set_client_hello_cb",
                "SSL_ech_get1_status",
                "OSSL_ECHSTORE_new_config",
                "OSSL_ECHSTORE_read_pem",
                "SSL_CTX_set1_echstore",
                "SSL_CTX_set_max_early_data",
            ):
                getattr(self.ssl, name)
        except (OSError, AttributeError) as exc:
            raise TLSFailure("openssl4_runtime_unavailable") from exc

    def require(self, result: Any, reason: str) -> None:
        if not result:
            raise TLSFailure(reason)

    def memory_bio(self) -> Any:
        bio = self.crypto.BIO_new(self.crypto.BIO_s_mem())
        self.require(bio, "bio_allocation")
        return bio

    def take(self, bio: Any, maximum: int) -> bytes:
        size = self.crypto.BIO_ctrl_pending(bio)
        if size > maximum:
            raise TLSFailure("tls_buffer_limit")
        if not size:
            return b""
        buf = self.ffi.new("unsigned char[]", size)
        if self.crypto.BIO_read(bio, buf, size) != size:
            raise TLSFailure("bio_read")
        return bytes(self.ffi.buffer(buf, size))

    def generate_ech(self, public_name: str) -> ECHKey:
        name = canonical_host(public_name).encode("ascii")
        store = self.ssl.OSSL_ECHSTORE_new(self.ffi.NULL, self.ffi.NULL)
        self.require(store, "ech_store_allocation")
        bio = self.ffi.NULL
        try:
            bio = self.memory_bio()
            suite = self.ffi.new("OSSL_HPKE_SUITE *", {"kem_id": 0x20, "kdf_id": 1, "aead_id": 1})
            self.require(
                self.ssl.OSSL_ECHSTORE_new_config(store, 0xFE0D, 0, name, suite[0]),
                "ech_key_generation",
            )
            self.require(self.ssl.OSSL_ECHSTORE_write_pem(store, 0, bio), "ech_key_encoding")
            return ECHKey.from_pem(self.take(bio, 65536))
        finally:
            self.crypto.BIO_free(bio)
            self.ssl.OSSL_ECHSTORE_free(store)


class NativeContext(Protocol):
    library: TLSLibrary
    _context: Any
    _closed: bool
    _sessions: dict[Any, TLSSession]

    def _check_thread(self) -> None: ...


class TLSContext:
    """Immutable ECH generation; existing sessions retain a closed context.

    Closing prevents new sessions, but does not invalidate callbacks or keys
    used by an in-flight session. Replacement publishes a new context only
    after all required durable keys have been installed successfully.
    """

    def __init__(self, library: TLSLibrary, keys: tuple[ECHKey, ...]) -> None:
        if not keys or len(keys) > 64:
            raise TLSFailure("ech_key_count")
        self.library = library
        self._owner = threading.get_ident()
        self._sessions: dict[Any, TLSSession] = {}
        self._closed = False
        ffi, ssl, crypto = library.ffi, library.ssl, library.crypto
        self._context = ssl.SSL_CTX_new(ssl.TLS_server_method())
        library.require(self._context, "tls_context_allocation")
        store = ffi.NULL
        try:
            store = ssl.OSSL_ECHSTORE_new(ffi.NULL, ffi.NULL)
            library.require(store, "ech_store_allocation")
            for key in keys:
                if ECHKey.from_pem(key.private_pem).configuration != key.configuration:
                    raise TLSFailure("ech_key_mapping")
                # BIO_new_mem_buf borrows the Python bytes only for this call.
                bio = crypto.BIO_new_mem_buf(key.private_pem, len(key.private_pem))
                library.require(bio, "bio_allocation")
                try:
                    library.require(ssl.OSSL_ECHSTORE_read_pem(store, bio, 1), "ech_key_load")
                finally:
                    crypto.BIO_free(bio)
            count = ffi.new("int *")
            library.require(ssl.OSSL_ECHSTORE_num_keys(store, count), "ech_key_count")
            if count[0] != len(keys):
                raise TLSFailure("ech_key_count")
            library.require(ssl.SSL_CTX_set1_echstore(self._context, store), "ech_context")
            # No resumed/early-data path may bypass origin inspection. TLS 1.2
            # is retained; session cache, tickets and renegotiation are disabled.
            library.require(ssl.SSL_CTX_ctrl(self._context, 123, 0x0303, ffi.NULL), "tls_minimum")
            ssl.SSL_CTX_ctrl(self._context, 44, 0, ffi.NULL)
            ssl.SSL_CTX_set_options(self._context, (1 << 14) | (1 << 30))
            library.require(ssl.SSL_CTX_set_num_tickets(self._context, 0), "tls_tickets")
            library.require(ssl.SSL_CTX_set_max_early_data(self._context, 0), "tls_early_data")
            self._hello_callback = ffi.callback("int(SSL *, int *, void *)", self._hello, error=0)
            self._alpn_callback = ffi.callback(
                "int(SSL *, const unsigned char **, unsigned char *,"
                "const unsigned char *, unsigned int, void *)",
                self._alpn,
                error=2,
            )
            ssl.SSL_CTX_set_client_hello_cb(self._context, self._hello_callback, ffi.NULL)
            ssl.SSL_CTX_set_alpn_select_cb(self._context, self._alpn_callback, ffi.NULL)
            self._status_callback: Any = ffi.callback("int(SSL *, void *)", self._status, error=2)
            library.require(
                ssl.SSL_CTX_callback_ctrl(
                    self._context, 63, ffi.cast("void (*)(void)", cast(Any, self._status_callback))
                ),
                "tls_status_callback",
            )
        except BaseException:
            self.close()
            raise
        finally:
            ssl.OSSL_ECHSTORE_free(store)

    def _check_thread(self) -> None:
        if self._owner != threading.get_ident():
            raise TLSFailure("tls_thread_ownership")

    def _status(self, connection: Any, unused: Any) -> int:
        try:
            self._check_thread()
            session = self._sessions[connection]
            if not session._ready:
                return 2
            from ads_sandbox_egress.tls_status import install_staples

            install_staples(self.library, connection, session.staples)
            return 0 if session.staples else 3
        except Exception:
            return 2

    def _hello(self, connection: Any, alert: Any, unused: Any) -> int:
        try:
            self._check_thread()
            session = self._sessions[connection]
            hello = session._capture_hello()
            if session.hello is not None and session.hello != hello:
                raise TLSFailure("changed_client_hello")
            session.hello = hello
            return 1 if session._ready else -1
        except Exception:
            alert[0] = 80  # internal_error, never include a policy payload.
            return 0

    def _alpn(
        self, connection: Any, out: Any, length: Any, offers: Any, size: int, unused: Any
    ) -> int:
        try:
            session = self._sessions[connection]
            if session.hello is None or not session._ready:
                return 2
            wire = bytes(self.library.ffi.buffer(offers, size))
            if parse_protocols(wire) != session.hello.protocols:
                return 2
            if session.selected is None:
                return 3  # no ACK: the real origin selected no ALPN.
            out[0], length[0] = session._selection, len(session.selected)
            return 0
        except Exception:
            return 2

    def session(self) -> TLSSession:
        self._check_thread()
        if self._closed:
            raise TLSFailure("closed_tls_context")
        if len(self._sessions) >= 128:
            raise TLSFailure("tls_connection_limit")
        return TLSSession(self)

    def close(self) -> None:
        self._check_thread()
        if not self._closed:
            self._closed = True
            self.library.ssl.SSL_CTX_free(self._context)


class TLSSession:
    """One bounded memory-BIO connection, paused before choosing a certificate."""

    staples: tuple[bytes | None, ...] = ()
    BUFFER_LIMIT = 131072

    def __init__(self, context: NativeContext) -> None:
        context._check_thread()
        if context._closed or len(context._sessions) >= 128:
            raise TLSFailure("tls_context_unavailable")
        self.context = context
        self.library = context.library
        ffi, ssl = self.library.ffi, self.library.ssl
        self._ssl = ssl.SSL_new(context._context)
        self.library.require(self._ssl, "tls_connection_allocation")
        self._input = self._output = ffi.NULL
        self._closed = self._ready = self.established = False
        self._handshake_bytes = 0
        self.hello: ClientHello | None = None
        self.selected: bytes | None = None
        self._selection = ffi.NULL
        try:
            self._input = self.library.memory_bio()
            self._output = self.library.memory_bio()
        except BaseException:
            self.library.crypto.BIO_free(self._input)
            self.library.crypto.BIO_free(self._output)
            ssl.SSL_free(self._ssl)
            raise
        ssl.SSL_set_bio(self._ssl, self._input, self._output)  # SSL owns both now.
        context._sessions[self._ssl] = self

    def _check(self) -> None:
        self.context._check_thread()
        if self._closed:
            raise TLSFailure("closed_tls_session")

    def _capture_hello(self) -> ClientHello:
        ffi, ssl = self.library.ffi, self.library.ssl

        def extension(kind: int) -> bytes | None:
            out, size = ffi.new("const unsigned char **"), ffi.new("size_t *")
            if ssl.SSL_client_hello_get0_ext(self._ssl, kind, out, size) != 1:
                return None
            if size[0] > 65535:
                raise TLSFailure("client_hello_limit")
            return bytes(ffi.buffer(out[0], size[0]))

        inner, outer = ffi.new("char **"), ffi.new("char **")
        status = ssl.SSL_ech_get1_status(self._ssl, inner, outer)
        try:
            outer_name = (
                cast(bytes, ffi.string(outer[0])).decode("ascii") if outer[0] != ffi.NULL else None
            )
            return parse_hello(extension(0), extension(16), extension(0xFE0D), status, outer_name)
        finally:
            self.library.crypto.CRYPTO_free(inner[0], ffi.NULL, 0)
            self.library.crypto.CRYPTO_free(outer[0], ffi.NULL, 0)

    def feed(self, encrypted: bytes) -> None:
        self._check()
        if not self.established:
            self._handshake_bytes += len(encrypted)
            if self._handshake_bytes > self.BUFFER_LIMIT:
                raise TLSFailure("tls_handshake_limit")
        size = self.library.crypto.BIO_ctrl_pending(self._input)
        if not encrypted or size + len(encrypted) > self.BUFFER_LIMIT:
            raise TLSFailure("tls_input_limit")
        if self.library.crypto.BIO_write(self._input, encrypted, len(encrypted)) != len(encrypted):
            raise TLSFailure("tls_input_write")

    def drain(self) -> bytes:
        self._check()
        return self.library.take(self._output, self.BUFFER_LIMIT)

    def _result(self, result: int) -> int:
        # SSL_get_error must immediately follow the operation on the SAME thread.
        error = self.library.ssl.SSL_get_error(self._ssl, result)
        if error not in (0, 2, 3, 6, 11):
            raise TLSFailure("tls_protocol_failure")
        if self.library.crypto.BIO_ctrl_pending(self._output) > self.BUFFER_LIMIT:
            raise TLSFailure("tls_output_limit")
        return int(error)

    def handshake(self) -> Literal["read", "write", "hello", "complete"]:
        self._check()
        if self.established:
            return "complete"
        self.library.crypto.ERR_clear_error()
        error = self._result(self.library.ssl.SSL_accept(self._ssl))
        if error == 11 and self.hello is not None and not self._ready:
            return "hello"
        if error == 2:
            return "read"
        if error == 3:
            return "write"
        if error != 0 or not self._ready:
            raise TLSFailure("tls_handshake_state")
        out, size = (
            self.library.ffi.new("const unsigned char **"),
            self.library.ffi.new("unsigned int *"),
        )
        self.library.ssl.SSL_get0_alpn_selected(self._ssl, out, size)
        selected = bytes(self.library.ffi.buffer(out[0], size[0])) if size[0] else None
        if selected != self.selected:
            raise TLSFailure("tls_alpn_mismatch")
        self.established = True
        return "complete"

    def resume(
        self,
        certificate_chain: tuple[bytes, ...],
        private_key: bytes,
        alpn: bytes | None,
        staples: tuple[bytes | None, ...] = (),
    ) -> None:
        self._check()
        if self.hello is None or self._ready or self.established:
            raise TLSFailure("tls_resume_state")
        if alpn is not None and alpn not in self.hello.protocols:
            raise TLSFailure("unoffered_origin_alpn")
        if (
            not certificate_chain
            or len(certificate_chain) > 16
            or not private_key
            or len(private_key) > 65536
            or sum(map(len, certificate_chain)) > 65536
        ):
            raise TLSFailure("tls_identity_limit")
        ffi, ssl, crypto = self.library.ffi, self.library.ssl, self.library.crypto
        # Unencrypted PKCS8 only. NULL PEM password callbacks must never prompt
        # on stdin. Certificate/key generation and defect mirroring are upstream
        # of this transport, not silently performed here.
        if not private_key.startswith(b"-----BEGIN PRIVATE KEY-----\n"):
            raise TLSFailure("tls_private_key_format")
        for index, pem in enumerate(certificate_chain):
            bio = crypto.BIO_new_mem_buf(pem, len(pem))
            self.library.require(bio, "bio_allocation")
            certificate = ffi.NULL
            try:
                certificate = crypto.PEM_read_bio_X509(bio, ffi.NULL, ffi.NULL, ffi.NULL)
                self.library.require(certificate, "tls_certificate_decode")
                result = (
                    ssl.SSL_use_certificate(self._ssl, certificate)
                    if index == 0
                    else ssl.SSL_ctrl(self._ssl, 89, 1, certificate)
                )
                self.library.require(result, "tls_certificate_install")
            finally:
                crypto.X509_free(certificate)
                crypto.BIO_free(bio)
        bio = crypto.BIO_new_mem_buf(private_key, len(private_key))
        self.library.require(bio, "bio_allocation")
        key = ffi.NULL
        try:
            key = crypto.PEM_read_bio_PrivateKey(bio, ffi.NULL, ffi.NULL, ffi.NULL)
            self.library.require(key, "tls_private_key_decode")
            self.library.require(ssl.SSL_use_PrivateKey(self._ssl, key), "tls_private_key_install")
            self.library.require(ssl.SSL_check_private_key(self._ssl), "tls_private_key_mismatch")
        finally:
            crypto.EVP_PKEY_free(key)
            crypto.BIO_free(bio)
        self.selected = alpn
        self._selection = ffi.new("unsigned char[]", alpn) if alpn else ffi.NULL
        if len(staples) > len(certificate_chain):
            raise TLSFailure("tls_status_chain_limit")
        self.staples = staples
        self._ready = True

    def read(self, maximum: int = 16384) -> bytes | None:
        """None means more ciphertext needed; empty means authenticated EOF."""
        self._check()
        if not self.established or not 1 <= maximum <= 16384:
            raise TLSFailure("tls_read_state")
        ffi = self.library.ffi
        buf, size = ffi.new("unsigned char[]", maximum), ffi.new("size_t *")
        self.library.crypto.ERR_clear_error()
        error = self._result(self.library.ssl.SSL_read_ex(self._ssl, buf, maximum, size))
        if error == 0:
            return bytes(ffi.buffer(buf, size[0]))
        if error == 6:
            return b""
        if error in (2, 3):
            return None
        raise TLSFailure("tls_read_failure")

    def write(self, plaintext: bytes) -> None:
        self._check()
        if not self.established or not 1 <= len(plaintext) <= 16384:
            raise TLSFailure("tls_write_state")
        if self.library.crypto.BIO_ctrl_pending(self._output) > self.BUFFER_LIMIT - 32768:
            raise TLSFailure("tls_output_backpressure")
        size = self.library.ffi.new("size_t *")
        self.library.crypto.ERR_clear_error()
        result = self.library.ssl.SSL_write_ex(self._ssl, plaintext, len(plaintext), size)
        if self._result(result) != 0 or size[0] != len(plaintext):
            # Memory BIO writes cannot block on the socket. Do not retry with a
            # different buffer or let an unexpected post-handshake state tunnel.
            raise TLSFailure("tls_write_failure")

    def shutdown(self) -> None:
        """Emit close_notify for normal completion, never for policy denial."""
        self._check()
        if not self.established:
            raise TLSFailure("tls_shutdown_state")
        self.library.crypto.ERR_clear_error()
        result = self.library.ssl.SSL_shutdown(self._ssl)
        if result < 0 and self._result(result) not in (2, 3):
            raise TLSFailure("tls_shutdown_failure")

    def close(self) -> None:
        self.context._check_thread()
        if not self._closed:
            self._closed = True
            self.context._sessions.pop(self._ssl, None)
            self.library.ssl.SSL_free(self._ssl)
