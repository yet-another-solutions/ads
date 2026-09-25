import asyncio
import base64
import ipaddress
import os

import pytest
from cryptography.hazmat.primitives import serialization
from h2.events import DataReceived
from hyperframe.frame import GoAwayFrame

from ads_commons.egress import ProjectEgressSnapshot
from ads_sandbox_egress.certificates import CertificatePairs, PairDestination
from ads_sandbox_egress.configuration import PolicyStore
from ads_sandbox_egress.destinations import DestinationBoundary
from ads_sandbox_egress.http2_proxy import HTTP2Proxy
from ads_sandbox_egress.identity_store import IdentityStore
from ads_sandbox_egress.membership import ConnectionMembership
from ads_sandbox_egress.origin_tls import OriginContext, inspect_origin
from ads_sandbox_egress.request_authorization import ConnectionTarget, RequestAuthorizer
from ads_sandbox_egress.streams import OwnedStream
from ads_sandbox_egress.tls import TLSContext
from ads_sandbox_egress.tls_transport import TLSStream
from test_certificates import pair_signer as pair_signer
from test_certificates import pair_state as pair_state
from test_http1_proxy import PUBLIC, Resolver, settings
from test_http2_proxy import Client, Origin, ended, headers, reset
from test_http2_shutdown import DrainingClient
from test_normalization import nginx_helper as nginx_helper
from test_origin_tls import certificate_fixture
from test_tls import native as native


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("graceful", [False, True])
async def test_ech_tls_http2_real_policy_and_original_origin_session(
    native, tmp_path, pair_signer, pair_state, nginx_helper, graceful
):
    library, directory, executable = native
    server_context, root, _, _ = certificate_fixture(tmp_path, "valid")
    server_context.set_alpn_protocols(["h2"])
    names = []
    server_context.set_servername_callback(lambda ssl, name, context: names.append(name))
    origin = Origin()
    tasks, errors, owners = set(), [], []
    stop = asyncio.Event()

    def spawn(coroutine):
        task = asyncio.create_task(coroutine)
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    async def origin_handler(reader, writer):
        try:
            assert writer.get_extra_info("ssl_object").selected_alpn_protocol() == "h2"
            await origin.handle(reader, writer)
        except (ConnectionError, TimeoutError):
            pass
        except Exception as error:
            errors.append(error)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, TimeoutError):
                pass

    origin_listener = await asyncio.start_server(
        lambda r, w: spawn(origin_handler(r, w)),
        "127.0.0.1",
        0,
        ssl=server_context,
        ssl_handshake_timeout=5,
        ssl_shutdown_timeout=1,
    )
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    pairs = CertificatePairs(store, pair_signer, "http://egress.invalid/crl/fixture")
    key = library.generate_ech("cover.example")
    frontend_context = TLSContext(library, (key,))
    origin_context = OriginContext(library, extra_trust=(root,), system_trust=False)
    policies = PolicyStore()
    await policies.install(
        ProjectEgressSnapshot(1, settings("/allowed", "/hold", port=443, protocol="https"))
    )
    boundary = DestinationBoundary((ipaddress.ip_network("10.0.0.0/8"),), (), "fixture")
    trust = tmp_path / "sandbox-trust.pem"
    trust.write_bytes(pair_signer.certificate.public_bytes(serialization.Encoding.PEM))
    handshakes, adoptions = [], []

    async def frontend(reader, writer):
        downstream = upstream = None
        membership = ConnectionMembership(Resolver(), boundary)
        target = ConnectionTarget(PUBLIC, 443, True, "origin.example")

        async def prepare(hello):
            nonlocal upstream
            assert hello.ech_accepted and hello.server_name == target.tls_name
            assert hello.protocols == (b"h2", b"http/1.1")
            # Explicit external socket/admission fixture. Everything after
            # socket creation is real origin TLS, pair storage and HTTP policy.
            r, w = await asyncio.open_connection(*origin_listener.sockets[0].getsockname())
            upstream, observed = await inspect_origin(
                r, w, origin_context, hello.server_name, hello.protocols
            )
            assert observed.verified and observed.selected_alpn == b"h2"
            handshakes.append(upstream.session)
            return pairs.valid(PairDestination(PUBLIC, 443, hello.server_name), observed)

        async def adopt(original):
            assert original is target and upstream is not None
            adoptions.append(upstream.session)
            return OwnedStream.tls(upstream)

        try:
            downstream = await TLSStream.accept(
                reader, writer, frontend_context, prepare, idle_timeout=0.15
            )
            owner = HTTP2Proxy(
                OwnedStream.tls(downstream),
                RequestAuthorizer(target, policies, membership, nginx_helper),
                adopt,
                idle_timeout=2,
            )
            owners.append(owner)
            await owner.run()
        except (ConnectionError, TimeoutError):
            pass
        except Exception as error:
            errors.append(error)
        finally:
            if downstream is not None:
                downstream.close()
            if upstream is not None:
                upstream.close()
            await membership.close()
            stop.set()

    listener = await asyncio.start_server(lambda r, w: spawn(frontend(r, w)), "127.0.0.1", 0)
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            str(executable),
            "s_client",
            "-connect",
            f"127.0.0.1:{listener.sockets[0].getsockname()[1]}",
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
            base64.b64encode(key.configuration).decode(),
            "-ech_outer_alpn",
            "http/1.1",
            "-quiet",
            env=dict(os.environ, LD_LIBRARY_PATH=str(directory), OPENSSL_CONF="/dev/null"),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        client = (DrainingClient if graceful else Client)(process.stdout, process.stdin)
        client.protocol.initiate_connection()

        async def request(stream_id, path):
            values = tuple(
                (name, b"https" if name == b":scheme" else value) for name, value in headers(path)
            )
            client.protocol.send_headers(stream_id, values, end_stream=True)
            await client.flush()

        await request(1, b"/denied")
        await client.until(lambda events: reset(events, 1))
        assert not origin.requests and not adoptions
        await request(3, b"/allowed")
        await client.until(lambda events: ended(events, 3))
        assert handshakes == adoptions and len(adoptions) == 1
        await request(5, b"/hold")
        await client.until(
            lambda events: any(isinstance(e, DataReceived) and e.stream_id == 5 for e in events)
        )

        # Download traffic extends actual TLS idle time while the client sends
        # no application frames (the body stays below WINDOW_UPDATE threshold).
        async def continue_download():
            for _ in range(8):
                await asyncio.sleep(0.05)
                origin.protocol.send_data(3, b"more")
                await origin.flush()
            origin.protocol.send_data(3, b"last", end_stream=True)
            await origin.flush()

        await asyncio.gather(continue_download(), client.until(lambda events: ended(events, 5)))
        assert not reset(client.events, 5)
        assert names == ["origin.example"] and not errors
        if graceful:
            origin.writer.write(GoAwayFrame(0, last_stream_id=3, error_code=0).serialize())
            await origin.writer.drain()
            await client.until(lambda events: bool(client.goaways))
            assert await asyncio.wait_for(process.stdout.read(), 2) == b""
            assert owners[0]._graceful
    finally:
        listener.close()
        origin_listener.close()
        if process is not None:
            if process.returncode is None:
                process.kill()
            await process.communicate()
        for owner in owners:
            owner.stop.set()
        await asyncio.gather(*tuple(tasks), return_exceptions=True)
        await listener.wait_closed()
        await origin_listener.wait_closed()
        frontend_context.close()
        origin_context.close()
        store.close()
        (tmp_path / "private.pem").unlink()
    assert not frontend_context._sessions and not origin_context._sessions
    assert not tasks and all(not owner._tasks for owner in owners)
