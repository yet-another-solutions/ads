import asyncio
import base64
import hashlib
import os
import ssl
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ads_sandbox_egress.identity_store import IdentityStore, StateIdentity, StateUnavailable
from ads_sandbox_egress.tls import ECHKey, TLSContext, TLSFailure, TLSLibrary, parse_hello
from ads_sandbox_egress.tls_transport import FrontendIdentity, TLSStream
from ech_probe import native_paths


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def native():
    value = os.environ.get("ADS_EGRESS_OPENSSL4_ROOT")
    if value is None:
        pytest.skip("real OpenSSL 4.0.2 runtime not provisioned")
    directory, executable = native_paths(Path(value))
    return TLSLibrary(directory), directory, executable


@pytest.fixture
def identity(tmp_path):
    private = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "secret.example")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("secret.example")]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), True
        )
        .sign(private, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    key = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (tmp_path / "trusted.pem").write_bytes(cert)  # Public fixture only.
    return cert, key, tmp_path / "trusted.pem"


def test_hello_preserves_opaque_alpn_order_and_absence():
    protocols = b"\x02h2\x08http/1.1\x02\xff\x01"
    sni = b"\x00\x11\x00\x00\x0eSecret.Example"
    hello = parse_hello(sni, len(protocols).to_bytes(2) + protocols, b"\x01", 1, "cover.example")
    assert hello.server_name == "secret.example"
    assert hello.protocols == (b"h2", b"http/1.1", b"\xff\x01")
    assert hello.ech_accepted
    assert parse_hello(None, None, None, -101, None).protocols == ()


@pytest.mark.parametrize(
    "sni,alpn,ech,status",
    [
        (b"\0\0", None, None, -101),
        (b"\0\x04\0\0\x01\xff", None, None, -101),
        (None, b"\0\x01\0", None, -101),
        (None, b"\0\x03\x02h", None, -101),
        (None, None, b"\x01", 4),
        (None, None, None, 1),
    ],
)
def test_malformed_or_unauthenticated_inner_hello_denied(sni, alpn, ech, status):
    with pytest.raises(TLSFailure):
        parse_hello(sni, alpn, ech, status, None)


def test_runtime_absent_fails_before_listener(tmp_path):
    with pytest.raises(TLSFailure, match="runtime_unavailable"):
        TLSLibrary(tmp_path)


def test_ech_encrypted_recovery_no_private_key_files(native, tmp_path):
    library, _, _ = native
    tmp_path.chmod(0o700)
    wrap = os.urandom(32)
    custody = StateIdentity(
        uuid4(), uuid4(), uuid4(), uuid4(), "pvc", "custody", hashlib.sha256(wrap).hexdigest()
    )
    store = IdentityStore(tmp_path, custody, wrap, capacity=2**20, create=True)
    key = library.generate_ech("cover.example")
    try:
        key.prepare(store, "ech/one")
        with pytest.raises(StateUnavailable):
            ECHKey.recover(store, "ech/one")
        store.advance("ech/one", "prepared", "published")
    finally:
        store.close()
    assert key.private_pem not in (tmp_path / "identity.sqlite").read_bytes()
    assert set(p.name for p in tmp_path.iterdir()) == {"identity.sqlite", "owner.lock"}
    store = IdentityStore(tmp_path, custody, wrap, capacity=2**20)
    try:
        recovered = ECHKey.recover(store, "ech/one")
        assert recovered == key
        context = TLSContext(library, (recovered,))
        context.close()
    finally:
        store.close()
    assert "PRIVATE" not in repr(key)
    with pytest.raises(TLSFailure, match="mapping"):
        TLSContext(library, (replace(key, configuration=b"substituted"),))


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
@pytest.mark.parametrize("offers", [True, False])
def test_memory_bio_real_stdlib_tls_and_context_retention(native, identity, version, offers):
    library, _, _ = native
    cert, key, trust = identity
    context = TLSContext(library, (library.generate_ech("cover.example"),))
    server = context.session()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_context = ssl.create_default_context(cafile=str(trust))
    client_context.maximum_version = version
    if offers:
        client_context.set_alpn_protocols(["h2", "http/1.1"])
    client = client_context.wrap_bio(incoming, outgoing, server_hostname="secret.example")
    context.close()  # Existing connection owns native context/callback lifetime.
    try:
        with pytest.raises(TLSFailure, match="closed_tls_context"):
            context.session()
        with pytest.raises(TLSFailure, match="resume_state"):
            server.resume((cert,), key, b"h2")
        complete = False
        for _ in range(20):
            try:
                client.do_handshake()
                complete = True
            except ssl.SSLWantReadError:
                pass
            if data := outgoing.read():
                server.feed(data)
            state = server.handshake()
            if state == "hello":
                assert server.hello.protocols == ((b"h2", b"http/1.1") if offers else ())
                assert not server.hello.ech_accepted
                assert not server.drain()  # No certificate flight before resume.
                with pytest.raises(TLSFailure, match="unoffered"):
                    server.resume((cert,), key, b"forged")
                server.resume((cert,), key, b"h2" if offers else None)
                state = server.handshake()
            if data := server.drain():
                incoming.write(data)
            if complete and state == "complete":
                break
        assert complete and server.established
        assert client.selected_alpn_protocol() == ("h2" if offers else None)
        client.write(b"request")
        server.feed(outgoing.read())
        assert server.read() == b"request"
        server.write(b"response")
        incoming.write(server.drain())
        assert client.read() == b"response"
        server.shutdown()
        incoming.write(server.drain())
        assert client.read() == b""
    finally:
        server.close()
        server.close()
    assert not context._sessions
    with pytest.raises(TLSFailure, match="closed_tls_session"):
        server.feed(b"x")


def test_memory_bio_limits_and_connection_admission(native):
    library, _, _ = native
    context = TLSContext(library, (library.generate_ech("cover.example"),))
    sessions = []
    try:
        for _ in range(128):
            sessions.append(context.session())
        with pytest.raises(TLSFailure, match="connection_limit"):
            context.session()
        connection = sessions[0]
        with pytest.raises(TLSFailure, match="handshake_limit"):
            connection.feed(b"x" * (connection.BUFFER_LIMIT + 1))
        with pytest.raises(TLSFailure, match="read_state"):
            connection.read()
        with pytest.raises(TLSFailure, match="write_state"):
            connection.write(b"application-before-handshake")
        with pytest.raises(TLSFailure, match="shutdown_state"):
            connection.shutdown()
    finally:
        for connection in sessions:
            connection.close()
        context.close()


@pytest.mark.parametrize("mode", ["ech", "plain", "grease", "foreign"])
@pytest.mark.parametrize("selected", [b"h2", b"http/1.1", None])
@pytest.mark.anyio
async def test_production_transport_with_native_client(native, identity, mode, selected):
    library, directory, executable = native
    cert, private, trust = identity
    key = library.generate_ech("cover.example")
    context = TLSContext(library, (key,))
    completed = asyncio.get_running_loop().create_future()
    observations = []

    async def prepare(hello):
        observations.append(hello)
        if mode == "foreign":
            raise TLSFailure("foreign_ech_not_authorized")
        # Certificate/protocol coordinator is the named external boundary here.
        # The ECH/TLS transport and client are real, not capability-test doubles.
        return FrontendIdentity((cert,), private, selected)

    async def accepted(reader, writer):
        stream = None
        try:
            stream = await TLSStream.accept(reader, writer, context, prepare)
            request = await stream.read()
            assert request == b"application-request\n"
            stream.write(b"application-response\n")
            await stream.drain()
            completed.set_result(True)
            # Test client is terminated by owner after verifying response.
            await stream.read()
        except Exception as exc:
            if not completed.done():
                completed.set_result(exc)
        finally:
            if stream:
                stream.close()

    tasks = set()

    def connected(reader, writer):
        task = asyncio.create_task(accepted(reader, writer))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    listener = await asyncio.start_server(connected, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    args = [
        str(executable),
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-servername",
        "secret.example",
        "-verify_hostname",
        "secret.example",
        "-verify_return_error",
        "-CAfile",
        str(trust),
        "-alpn",
        "h2,http/1.1",
        "-quiet",
    ]
    if mode in ("ech", "foreign"):
        client_key = library.generate_ech("cover.example") if mode == "foreign" else key
        args += [
            "-ech_config_list",
            base64.b64encode(client_key.configuration).decode(),
            "-ech_outer_alpn",
            "http/1.1",
        ]
    elif mode == "grease":
        args += ["-ech_grease"]
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            env=dict(os.environ, LD_LIBRARY_PATH=str(directory), OPENSSL_CONF="/dev/null"),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        process.stdin.write(b"application-request\n")
        await process.stdin.drain()
        async with asyncio.timeout(5):
            outcome = await completed
            if mode == "foreign":
                assert isinstance(outcome, TLSFailure)
                assert not observations[0].ech_accepted
            else:
                assert outcome is True
                assert await process.stdout.readline() == b"application-response\n"
                assert observations[0].protocols == (b"h2", b"http/1.1")
                assert observations[0].ech_accepted == (mode == "ech")
                assert observations[0].server_name == "secret.example"
    finally:
        listener.close()
        if process is not None:
            if process.returncode is None:
                process.kill()
            await process.communicate()
        for task in tuple(tasks):
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await listener.wait_closed()
        context.close()
    assert not context._sessions


@pytest.mark.anyio
async def test_handshake_deadline_and_cancellation_close_native_session(native):
    library, _, _ = native
    context = TLSContext(library, (library.generate_ech("cover.example"),))
    completed = asyncio.get_running_loop().create_future()

    async def prepare(hello):
        raise AssertionError("must not prepare an absent hello")

    async def connected(reader, writer):
        try:
            await TLSStream.accept(reader, writer, context, prepare, handshake_timeout=0.05)
        except TimeoutError:
            completed.set_result(True)

    listener = await asyncio.start_server(connected, "127.0.0.1", 0)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", listener.sockets[0].getsockname()[1]
    )
    try:
        assert await asyncio.wait_for(completed, 2)
        with pytest.raises(ConnectionResetError):
            await reader.read()
        assert not context._sessions
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
        listener.close()
        await listener.wait_closed()
        context.close()


@pytest.mark.anyio
async def test_cancelled_handshake_frees_state_and_resets_peer(native):
    library, _, _ = native
    context = TLSContext(library, (library.generate_ech("cover.example"),))
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    tasks = []

    async def prepare(hello):
        raise AssertionError("no hello")

    async def connected(reader, writer):
        entered.set()
        try:
            await TLSStream.accept(reader, writer, context, prepare)
        except asyncio.CancelledError:
            cancelled.set()

    def accepted(reader, writer):
        tasks.append(asyncio.create_task(connected(reader, writer)))

    listener = await asyncio.start_server(accepted, "127.0.0.1", 0)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", listener.sockets[0].getsockname()[1]
    )
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert len(context._sessions) == 1
        tasks[0].cancel()
        await asyncio.wait_for(cancelled.wait(), 2)
        assert not context._sessions
        with pytest.raises(ConnectionResetError):
            await reader.read()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
        await asyncio.gather(*tasks, return_exceptions=True)
        listener.close()
        await listener.wait_closed()
        context.close()
