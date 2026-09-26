"""Native capability proof, NOT a production TLS transport.

Only public OpenSSL 4 APIs are bound. No compile, internal pointer extraction,
stdlib monkey patch, opaque ECH tunnel, or certificate-verification bypass.
"""

from __future__ import annotations

import base64
import os
import re
import select
import socket
import ssl as python_ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from cffi import FFI

_ABI = """
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct bio_st BIO;
typedef struct ossl_echstore_st OSSL_ECHSTORE;
typedef struct { uint16_t kem_id; uint16_t kdf_id; uint16_t aead_id; } OSSL_HPKE_SUITE;
const char *OpenSSL_version(int);
const SSL_METHOD *TLS_server_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *);
void SSL_CTX_free(SSL_CTX *);
SSL *SSL_new(SSL_CTX *);
void SSL_free(SSL *);
int SSL_set_fd(SSL *, int);
int SSL_accept(SSL *);
int SSL_get_error(const SSL *, int);
int SSL_use_certificate_chain_file(SSL *, const char *);
int SSL_use_PrivateKey_file(SSL *, const char *, int);
int SSL_check_private_key(const SSL *);
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
int OSSL_ECHSTORE_new_config(OSSL_ECHSTORE *, uint16_t, uint8_t, const char *, OSSL_HPKE_SUITE);
int OSSL_ECHSTORE_write_pem(OSSL_ECHSTORE *, int, BIO *);
int OSSL_ECHSTORE_num_keys(const OSSL_ECHSTORE *, int *);
int SSL_CTX_set1_echstore(SSL_CTX *, OSSL_ECHSTORE *);
BIO *BIO_new_file(const char *, const char *);
int BIO_free(BIO *);
void CRYPTO_free(void *, const char *, int);
unsigned long ERR_get_error(void);
void ERR_error_string_n(unsigned long, char *, size_t);
int SSL_read_ex(SSL *, void *, size_t, size_t *);
int SSL_write_ex(SSL *, const void *, size_t, size_t *);
int SSL_shutdown(SSL *);
"""


def native_paths(root: Path) -> tuple[Path, Path]:
    libraries = tuple(root.glob("usr/lib/*-linux-gnu/libssl.so.4"))
    if len(libraries) != 1 or not (root / "usr/bin/openssl").is_file():
        raise ValueError("isolated OpenSSL 4 library and executable required")
    return libraries[0].parent, root / "usr/bin/openssl"


def run_probe(
    root: Path, *, mode: str = "ech", origin_alpn: str | None = "http/1.1"
) -> dict[str, object]:
    """Prove public-ABI pause/resume against independent native CLI client."""
    if mode not in ("ech", "plain", "grease", "foreign", "bad-certificate"):
        raise ValueError("invalid proof mode")
    libraries, executable = native_paths(root)
    env = dict(os.environ, LD_LIBRARY_PATH=str(libraries), OPENSSL_CONF="/dev/null")
    ffi = FFI()
    ffi.cdef(_ABI)
    crypto = ffi.dlopen(str(libraries / "libcrypto.so.4"))
    tls = ffi.dlopen(str(libraries / "libssl.so.4"))
    version = ffi.string(crypto.OpenSSL_version(0)).decode("ascii")
    if not version.startswith("OpenSSL 4.0.2 "):
        raise ValueError("proof is pinned to OpenSSL 4.0.2")

    def errors():
        values = []
        while code := crypto.ERR_get_error():
            buf = ffi.new("char[]", 256)
            crypto.ERR_error_string_n(code, buf, 256)
            values.append(ffi.string(buf).decode("ascii"))
        return values

    def extension(connection, kind):
        out, size = ffi.new("const unsigned char **"), ffi.new("size_t *")
        if tls.SSL_client_hello_get0_ext(connection, kind, out, size) != 1:
            return None
        assert size[0] <= 65535
        return bytes(ffi.buffer(out[0], size[0]))

    def ech_status(connection):
        inner, outer = ffi.new("char **"), ffi.new("char **")
        result = tls.SSL_ech_get1_status(connection, inner, outer)
        try:
            names = tuple(
                ffi.string(p[0]).decode("ascii") if p[0] != ffi.NULL else None
                for p in (inner, outer)
            )
            return result, names
        finally:
            for pointer in (inner, outer):
                crypto.CRYPTO_free(pointer[0], ffi.NULL, 0)

    def command(*args):
        return subprocess.run(
            [str(executable), *map(str, args)],
            env=env,
            check=True,
            capture_output=True,
            timeout=15,
        )

    def config(path):
        # Public configuration only, never print or return private PEM contents.
        match = re.search(
            rb"-----BEGIN ECHCONFIG-----\s+(.*?)-----END ECHCONFIG-----",
            path.read_bytes(),
            re.S,
        )
        assert match is not None
        decoded = base64.b64decode(match[1])
        assert decoded[2:4] == b"\xfe\x0d"  # RFC 9849 ECHConfig version.
        return base64.b64encode(decoded).decode("ascii")

    def generate_key(path):
        # Generate through Python's public ABI binding, persist, free the
        # generation store, then reload into the serving store below.
        generation = tls.OSSL_ECHSTORE_new(ffi.NULL, ffi.NULL)
        assert generation != ffi.NULL, errors()
        destination = ffi.NULL
        try:
            suite = ffi.new("OSSL_HPKE_SUITE *", {"kem_id": 0x20, "kdf_id": 1, "aead_id": 1})
            assert (
                tls.OSSL_ECHSTORE_new_config(generation, 0xFE0D, 0, b"cover.example", suite[0]) == 1
            ), errors()
            path.touch(mode=0o600, exist_ok=False)
            destination = crypto.BIO_new_file(os.fsencode(path), b"w")
            assert destination != ffi.NULL, errors()
            assert tls.OSSL_ECHSTORE_write_pem(generation, 0, destination) == 1, errors()
        finally:
            if destination != ffi.NULL:
                crypto.BIO_free(destination)
            tls.OSSL_ECHSTORE_free(generation)

    context = connection = store = bio = ffi.NULL
    peer = client = listener = origin_listener = origin_thread = upstream = None
    origin_error: list[BaseException] = []
    origin_observed: dict[str, object] = {}
    result: dict[str, object] = {"openssl": version, "mode": mode}
    with tempfile.TemporaryDirectory(prefix="ads-ech-proof-") as temporary:
        folder = Path(temporary)
        pem, crt, key = (folder / name for name in ("ech.pem", "cert.pem", "key.pem"))
        try:
            generate_key(pem)
            command(
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-noenc",
                "-days",
                "1",
                "-subj",
                "/CN=secret.example",
                "-addext",
                "subjectAltName=DNS:secret.example",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
                "-keyout",
                key,
                "-out",
                crt,
            )
            store = tls.OSSL_ECHSTORE_new(ffi.NULL, ffi.NULL)
            assert store != ffi.NULL, errors()
            bio = crypto.BIO_new_file(os.fsencode(pem), b"r")
            assert bio != ffi.NULL, errors()
            assert tls.OSSL_ECHSTORE_read_pem(store, bio, 1) == 1, errors()
            count = ffi.new("int *")
            assert tls.OSSL_ECHSTORE_num_keys(store, count) == 1 and count[0] == 1
            context = tls.SSL_CTX_new(tls.TLS_server_method())
            assert context != ffi.NULL, errors()
            assert tls.SSL_CTX_set1_echstore(context, store) == 1, errors()
            ready = False
            calls = []
            callback_errors = []
            selected_protocol = None
            selection = ffi.NULL

            @ffi.callback("int(SSL *, int *, void *)", error=0)
            def hello(ssl, alert, _):
                try:
                    calls.append(
                        {
                            "sni": extension(ssl, 0),
                            "alpn": extension(ssl, 16),
                            "ech": extension(ssl, 0xFE0D),
                            "status": ech_status(ssl),
                        }
                    )
                    return 1 if ready else -1
                except Exception as exc:
                    callback_errors.append(type(exc).__name__)
                    alert[0] = 80
                    return 0

            @ffi.callback(
                "int(SSL *, const unsigned char **, unsigned char *,"
                "const unsigned char *, unsigned int, void *)",
                error=2,
            )
            def alpn(ssl, out, out_length, offers, length, _):
                if bytes(ffi.buffer(offers, length)) != b"\x02h2\x08http/1.1":
                    callback_errors.append("unexpected ALPN order")
                    return 2
                if selected_protocol is None:
                    return 3  # SSL_TLSEXT_ERR_NOACK: origin selected no ALPN.
                out[0], out_length[0] = selection, len(selected_protocol)
                return 0

            tls.SSL_CTX_set_client_hello_cb(context, hello, ffi.NULL)
            tls.SSL_CTX_set_alpn_select_cb(context, alpn, ffi.NULL)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            args = [
                str(executable),
                "s_client",
                "-connect",
                f"127.0.0.1:{listener.getsockname()[1]}",
                "-servername",
                "secret.example",
                "-verify_hostname",
                "wrong.example" if mode == "bad-certificate" else "secret.example",
                "-verify_return_error",
                "-CAfile",
                str(crt),
                "-alpn",
                "h2,http/1.1",
                "-quiet",
            ]
            if mode in ("ech", "foreign", "bad-certificate"):
                selected = pem
                if mode == "foreign":
                    selected = folder / "foreign.pem"
                    command("ech", "-public_name", "cover.example", "-out", selected)
                args += ["-ech_config_list", config(selected), "-ech_outer_alpn", "http/1.1"]
            elif mode == "grease":
                args += ["-ech_grease"]
            client = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            peer, _ = listener.accept()
            peer.setblocking(False)
            connection = tls.SSL_new(context)
            assert connection != ffi.NULL, errors()
            assert tls.SSL_set_fd(connection, peer.fileno()) == 1
            deadline = time.monotonic() + 10

            def wait_io(error):
                remaining = deadline - time.monotonic()
                assert remaining > 0, "native handshake deadline"
                read, write, _ = select.select(
                    [peer] if error == 2 else [],
                    [peer] if error == 3 else [],
                    [],
                    remaining,
                )
                assert read or write, "native socket deadline"

            def handshake():
                while True:
                    ret = tls.SSL_accept(connection)
                    if ret == 1:
                        return 0
                    error = tls.SSL_get_error(connection, ret)
                    if error not in (2, 3):
                        return error
                    wait_io(error)

            assert handshake() == 11, errors()  # SSL_ERROR_WANT_CLIENT_HELLO_CB
            assert not callback_errors
            observation = calls[0]
            accepted = observation["status"][0] == 1 and observation["ech"] == b"\x01"
            result.update(
                ech_accepted=accepted,
                ech_status=observation["status"][0],
                paused_before_certificate=True,
            )
            if mode == "foreign":
                assert not accepted
                assert b"cover.example" in observation["sni"]
                peer.close()
                peer = None
                stdout, _ = client.communicate(timeout=5)
                assert client.returncode != 0 and not stdout
                result.update(rejected_before_upstream=True, application_exchange=False)
                return result
            assert accepted is (mode in ("ech", "bad-certificate"))
            assert b"secret.example" in observation["sni"]
            assert observation["alpn"] == b"\0\x0c\x02h2\x08http/1.1"

            # Only after the inner ClientHello was inspected and suspended:
            # establish a SECOND actual TLS leg and obtain origin's ALPN choice.
            origin_context = python_ssl.SSLContext(python_ssl.PROTOCOL_TLS_SERVER)
            origin_context.load_cert_chain(crt, key)
            if origin_alpn is not None:
                origin_context.set_alpn_protocols([origin_alpn])
            origin_listener = socket.socket()
            origin_listener.bind(("127.0.0.1", 0))
            origin_listener.listen(1)
            origin_listener.settimeout(5)

            def origin():
                try:
                    raw, _ = origin_listener.accept()
                    raw.settimeout(5)
                    with origin_context.wrap_socket(raw, server_side=True) as stream:
                        origin_observed["alpn"] = stream.selected_alpn_protocol()
                        data = stream.recv(1024)
                        origin_observed["request"] = data
                        if data:
                            assert data == b"proof-request\n"
                            stream.sendall(b"proof-response\n")
                except BaseException as exc:
                    origin_error.append(exc)

            origin_thread = threading.Thread(target=origin, daemon=True)
            origin_thread.start()
            upstream_context = python_ssl.create_default_context(cafile=str(crt))
            remaining = observation["alpn"][2:]
            offered = []
            while remaining:
                length = remaining[0]
                assert 0 < length < len(remaining)
                offered.append(remaining[1 : 1 + length].decode("ascii"))
                remaining = remaining[1 + length :]
            assert offered == ["h2", "http/1.1"]
            upstream_context.set_alpn_protocols(offered)
            upstream = upstream_context.wrap_socket(
                socket.create_connection(origin_listener.getsockname(), timeout=5),
                server_hostname="secret.example",
            )
            selected_protocol = upstream.selected_alpn_protocol()
            assert selected_protocol == origin_alpn
            selection = ffi.new("unsigned char[]", (selected_protocol or "").encode("ascii"))
            assert upstream.getpeercert(binary_form=True)
            assert not origin_observed.get("request")
            assert tls.SSL_use_certificate_chain_file(connection, os.fsencode(crt)) == 1, errors()
            assert tls.SSL_use_PrivateKey_file(connection, os.fsencode(key), 1) == 1, errors()
            assert tls.SSL_check_private_key(connection) == 1, errors()
            ready = True
            handshake_error = handshake()
            if mode == "bad-certificate":
                assert handshake_error != 0
                stdout, stderr = client.communicate(timeout=5)
                assert client.returncode != 0 and not stdout
                assert b"hostname mismatch" in stderr
                result.update(certificate_failure_preserved=True, application_exchange=False)
                return result
            assert handshake_error == 0, errors()
            assert not callback_errors
            selected, size = ffi.new("const unsigned char **"), ffi.new("unsigned int *")
            tls.SSL_get0_alpn_selected(connection, selected, size)
            negotiated = bytes(ffi.buffer(selected[0], size[0])) if size[0] else None
            assert negotiated == (origin_alpn.encode("ascii") if origin_alpn else None)
            assert (ech_status(connection)[0] == 1) is accepted
            client.stdin.write(b"proof-request\n")
            client.stdin.flush()
            output, count = ffi.new("char[]", 1024), ffi.new("size_t *")
            while True:
                ret = tls.SSL_read_ex(connection, output, 1024, count)
                if ret == 1:
                    break
                error = tls.SSL_get_error(connection, ret)
                assert error in (2, 3), errors()
                wait_io(error)
            data = bytes(ffi.buffer(output, count[0]))
            assert data == b"proof-request\n"
            upstream.sendall(data)
            response = upstream.recv(1024)
            assert response == b"proof-response\n"
            assert tls.SSL_write_ex(connection, response, len(response), count) == 1, errors()
            assert count[0] == len(response)
            tls.SSL_shutdown(connection)
            stdout, stderr = client.communicate(timeout=5)
            assert response in stdout and client.returncode == 0, stderr.decode("ascii", "replace")
            origin_thread.join(timeout=5)
            assert not origin_thread.is_alive() and not origin_error
            result.update(
                inner_sni="secret.example",
                offered_alpn=["h2", "http/1.1"],
                selected_alpn=origin_alpn,
                callback_calls=len(calls),
                application_exchange=True,
                client_certificate_validation=True,
                origin_certificate_validation=True,
                upstream_contact_after_pause=True,
                python_generated_and_reloaded_key=True,
                ech_config_version="0xfe0d",
            )
            return result
        finally:
            if client is not None and client.poll() is None:
                client.kill()
                client.communicate()
            if upstream is not None:
                upstream.close()
            if origin_thread is not None:
                origin_thread.join(timeout=6)
                assert not origin_thread.is_alive(), "origin helper leaked"
            for sock in (peer, listener, origin_listener):
                if sock is not None:
                    sock.close()
            if connection != ffi.NULL:
                tls.SSL_free(connection)
            if context != ffi.NULL:
                tls.SSL_CTX_free(context)
            if bio != ffi.NULL:
                crypto.BIO_free(bio)
            if store != ffi.NULL:
                tls.OSSL_ECHSTORE_free(store)
