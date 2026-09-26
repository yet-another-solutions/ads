import asyncio
import base64
import ipaddress
import os
import ssl
import time
from contextlib import asynccontextmanager

import pytest
from cryptography.hazmat.primitives import serialization

from ads_commons.egress import ProjectEgressSnapshot
from ads_sandbox_egress.certificates import CertificatePairs
from ads_sandbox_egress.configuration import PolicyStore
from ads_sandbox_egress.connections import Connections, InterfaceConnector
from ads_sandbox_egress.destinations import DestinationBoundary
from ads_sandbox_egress.ech_lifecycle import ECHLifecycle
from ads_sandbox_egress.identity_store import IdentityStore
from ads_sandbox_egress.origin_tls import OriginContext
from ads_sandbox_egress.policy import RequestDenied
from test_certificate_mirror import mirror_fixture
from test_certificates import pair_signer as pair_signer
from test_certificates import pair_state as pair_state
from test_http1_proxy import PUBLIC, Resolver, close_client, settings
from test_http2_proxy import Client, Origin, ended, headers, reset
from test_normalization import nginx_helper as nginx_helper
from test_origin_tls import certificate_fixture
from test_tls import anyio_backend as anyio_backend
from test_tls import native as native


@asynccontextmanager
async def connection_lab(
    native,
    tmp_path,
    pair_signer,
    pair_state,
    normalizer,
    *,
    secure=False,
    protocol=None,
    defect="valid",
    configured=True,
    maximum=128,
):
    library, _, _ = native
    tls, root, _, _ = certificate_fixture(tmp_path, defect)
    if protocol:
        tls.set_alpn_protocols([protocol])
    requests, sockets, names, writers, tasks = [], [], [], set(), set()
    closing = False
    tls.set_servername_callback(lambda ssl, name, context: names.append(name))
    h2 = Origin()

    async def origin(r, w):
        writers.add(w)
        try:
            if protocol == "h2":
                await h2.handle(r, w)
            else:
                request = await r.readuntil(b"\r\n\r\n")
                requests.append(request)
                w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                await w.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            await close_client(w)
            writers.discard(w)

    def spawn(r, w):
        if closing:
            w.transport.abort()
            return
        task = asyncio.create_task(origin(r, w))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    listener = await asyncio.start_server(
        spawn,
        "127.0.0.1",
        0,
        **({"ssl": tls, "ssl_shutdown_timeout": 1} if secure else {}),
    )
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    ech = ECHLifecycle(
        store,
        library,
        public_name="cover.example",
        handshake_window=10,
        now=time.time(),
        initialize=True,
    )
    origin_context = OriginContext(library, extra_trust=(root,), system_trust=False)
    policies = PolicyStore()
    if configured:
        await policies.install(
            ProjectEgressSnapshot(
                1,
                settings(
                    "/allowed", port=443 if secure else 80, protocol="https" if secure else "http"
                ),
            )
        )
    boundary = DestinationBoundary((ipaddress.ip_network("10.0.0.0/8"),), (), "fixture")

    async def dial(address, port):
        # Named external boundary only. Real production interface routing is a
        # separate kernel proof; everything after socket acquisition is real.
        assert address == PUBLIC and port == (443 if secure else 80)
        sockets.append((address, port))
        return await asyncio.open_connection(*listener.sockets[0].getsockname())

    owner = Connections(
        policies,
        boundary,
        Resolver(),
        normalizer,
        ech,
        origin_context,
        CertificatePairs(store, pair_signer, "http://egress.invalid/crl/test"),
        mirror_fixture(library, pair_signer),
        dial,
        maximum=maximum,
    )
    front = await asyncio.start_server(
        lambda r, w: owner.accept(r, w, PUBLIC, 443 if secure else 80), "127.0.0.1", 0
    )
    try:
        yield owner, front.sockets[0].getsockname(), ech, requests, sockets, names, h2
    finally:
        closing = True
        front.close()
        await owner.close()
        listener.close()
        for writer in tuple(writers):
            writer.transport.abort()
        for task in tuple(tasks):
            task.cancel()
        await asyncio.gather(*tuple(tasks), return_exceptions=True)
        # gather of already-completed eager tasks may not suspend. Let their
        # registered done callbacks run before asserting the ownership set.
        await asyncio.sleep(0)
        await front.wait_closed()
        await listener.wait_closed()
        ech.close()
        origin_context.close()
        store.close()
        (tmp_path / "private.pem").unlink()
    assert not owner._tasks and not origin_context._sessions
    assert not tasks and not writers


@pytest.mark.anyio
@pytest.mark.parametrize("case", ["allowed", "denied", "unconfigured", "identity", "connect"])
async def test_plain_production_owner_admission(
    native, tmp_path, pair_signer, pair_state, nginx_helper, case
):
    async with connection_lab(
        native, tmp_path, pair_signer, pair_state, nginx_helper, configured=case != "unconfigured"
    ) as (_, address, _, requests, sockets, _, _):
        reader, writer = await asyncio.open_connection(*address)
        method = b"CONNECT" if case == "connect" else b"GET"
        path = b"/denied" if case == "denied" else b"/allowed"
        host = b"other.example" if case == "identity" else b"origin.example"
        try:
            writer.write(method + b" " + path + b" HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")
            await writer.drain()
            if case == "allowed":
                response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
                assert response.startswith(b"HTTP/1.1 200")
                assert await asyncio.wait_for(reader.readexactly(2), 3) == b"ok"
                assert len(requests) == len(sockets) == 1
            else:
                with pytest.raises(ConnectionResetError):
                    await asyncio.wait_for(reader.read(), 3)
                assert not requests and not sockets
        finally:
            await close_client(writer)


@pytest.mark.anyio
@pytest.mark.parametrize("secure", [False, True])
async def test_production_owner_h2_denied_stream_does_not_kill_allowed(
    native, tmp_path, pair_signer, pair_state, nginx_helper, secure
):
    async with connection_lab(
        native, tmp_path, pair_signer, pair_state, nginx_helper, secure=secure, protocol="h2"
    ) as (_, address, _, _, sockets, names, h2):
        context = ssl.create_default_context()
        context.load_verify_locations(
            cadata=pair_signer.certificate.public_bytes(serialization.Encoding.PEM).decode()
        )
        context.set_alpn_protocols(["h2", "http/1.1"])
        reader, writer = await asyncio.open_connection(
            *address, **({"ssl": context, "server_hostname": "origin.example"} if secure else {})
        )
        client = Client(reader, writer)
        client.protocol.initiate_connection()
        try:
            for stream, path in [(1, b"/denied"), (3, b"/allowed")]:
                values = tuple(
                    (name, b"https" if secure else b"http") if name == b":scheme" else (name, value)
                    for name, value in headers(path)
                )
                client.protocol.send_headers(stream, values, end_stream=True)
                await client.flush()
                await client.until(
                    lambda events, sid=stream: (
                        reset(events, sid) if sid == 1 else ended(events, sid)
                    )
                )
                if stream == 1:
                    assert not h2.requests and len(sockets) == int(secure)
            assert len(sockets) == 1 and len(h2.requests) == 1
            assert names == (["origin.example"] if secure else [])
        finally:
            await close_client(writer)


@pytest.mark.anyio
@pytest.mark.parametrize("protocol", [None, "http/1.1", "h2"])
async def test_production_ech_owner_uses_inner_identity(
    native, tmp_path, pair_signer, pair_state, nginx_helper, protocol
):
    _, directory, executable = native
    async with connection_lab(
        native, tmp_path, pair_signer, pair_state, nginx_helper, secure=True, protocol=protocol
    ) as (_, address, ech, requests, sockets, names, h2):
        trust = tmp_path / "trust.pem"
        trust.write_bytes(pair_signer.certificate.public_bytes(serialization.Encoding.PEM))
        process = await asyncio.create_subprocess_exec(
            str(executable),
            "s_client",
            "-connect",
            f"{address[0]}:{address[1]}",
            "-servername",
            "origin.example",
            "-verify_hostname",
            "origin.example",
            "-verify_return_error",
            "-CAfile",
            str(trust),
            "-alpn",
            "h2,http/1.1",
            "-ech_config_list",
            base64.b64encode(ech.configuration).decode(),
            "-ech_outer_alpn",
            "http/1.1",
            "-quiet",
            env=dict(os.environ, LD_LIBRARY_PATH=str(directory), OPENSSL_CONF="/dev/null"),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            if protocol == "h2":
                client = Client(process.stdout, process.stdin)
                client.protocol.initiate_connection()
                values = tuple(
                    (n, b"https" if n == b":scheme" else v) for n, v in headers(b"/allowed")
                )
                client.protocol.send_headers(1, values, end_stream=True)
                await client.flush()
                await client.until(lambda events: ended(events, 1))
                assert len(h2.requests) == 1
            else:
                process.stdin.write(b"GET /allowed HTTP/1.1\r\nHost: origin.example\r\n\r\n")
                await process.stdin.drain()
                response = await asyncio.wait_for(process.stdout.readuntil(b"\r\n\r\n"), 5)
                assert response.startswith(b"HTTP/1.1 200")
                assert await process.stdout.readexactly(2) == b"ok"
                assert len(requests) == 1
            assert len(sockets) == 1 and names == ["origin.example"]
        finally:
            if process.returncode is None:
                process.kill()
            await process.communicate()


@pytest.mark.anyio
async def test_capacity_and_shutdown_cancel_classification_without_origin(
    native, tmp_path, pair_signer, pair_state, nginx_helper
):
    async with connection_lab(
        native, tmp_path, pair_signer, pair_state, nginx_helper, maximum=1
    ) as (owner, address, _, _, sockets, _, _):
        first, first_writer = await asyncio.open_connection(*address)
        second, second_writer = await asyncio.open_connection(*address)
        try:
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(second.read(), 2)
            await owner.close()
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(first.read(), 2)
            assert not owner._tasks and not sockets
        finally:
            await close_client(first_writer)
            await close_client(second_writer)


@pytest.mark.anyio
async def test_interface_connector_denies_private_before_socket():
    boundary = DestinationBoundary((ipaddress.ip_network("10.0.0.0/8"),), (), "fixture")
    with pytest.raises(RequestDenied):
        await InterfaceConnector("no-such-device", boundary)(ipaddress.ip_address("127.0.0.1"), 80)


@pytest.mark.anyio
@pytest.mark.parametrize("strict", [False, True])
async def test_owner_does_not_repair_expired_origin_certificate(
    native, tmp_path, pair_signer, pair_state, nginx_helper, strict
):
    async with connection_lab(
        native, tmp_path, pair_signer, pair_state, nginx_helper, secure=True, defect="expired"
    ) as (_, address, _, requests, sockets, _, _):
        context = ssl.create_default_context()
        context.load_verify_locations(
            cadata=pair_signer.certificate.public_bytes(serialization.Encoding.PEM).decode()
        )
        if not strict:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if strict:
            with pytest.raises(ssl.SSLCertVerificationError, match="expired"):
                await asyncio.open_connection(
                    *address, ssl=context, server_hostname="origin.example"
                )
            assert len(sockets) == 1 and not requests
        else:
            reader, writer = await asyncio.open_connection(
                *address, ssl=context, server_hostname="origin.example"
            )
            try:
                writer.write(b"GET /allowed HTTP/1.1\r\nHost: origin.example\r\n\r\n")
                await writer.drain()
                assert (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)).startswith(
                    b"HTTP/1.1 200"
                )
                assert await reader.readexactly(2) == b"ok"
                assert len(sockets) == len(requests) == 1
            finally:
                await close_client(writer)


@pytest.mark.anyio
async def test_owner_rejects_unsupported_origin_alpn_without_downgrade(
    native, tmp_path, pair_signer, pair_state, nginx_helper
):
    async with connection_lab(
        native,
        tmp_path,
        pair_signer,
        pair_state,
        nginx_helper,
        secure=True,
        protocol="unsupported",
    ) as (_, address, _, requests, sockets, _, _):
        context = ssl.create_default_context()
        context.load_verify_locations(
            cadata=pair_signer.certificate.public_bytes(serialization.Encoding.PEM).decode()
        )
        context.set_alpn_protocols(["unsupported", "http/1.1"])
        with pytest.raises(ConnectionResetError):
            await asyncio.open_connection(*address, ssl=context, server_hostname="origin.example")
        assert len(sockets) == 1 and not requests
