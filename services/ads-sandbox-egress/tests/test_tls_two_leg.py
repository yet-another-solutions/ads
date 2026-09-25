import asyncio
import base64
import os

import pytest

from ads_sandbox_egress.origin_tls import OriginContext, inspect_origin
from ads_sandbox_egress.tls import TLSContext
from ads_sandbox_egress.tls_transport import FrontendIdentity, TLSStream
from test_origin_tls import certificate_fixture
from test_tls import anyio_backend as anyio_backend
from test_tls import native as native


@pytest.mark.anyio
@pytest.mark.parametrize("selected", ["h2", "http/1.1", None])
async def test_actual_ech_to_actual_verified_origin_no_application_before_resume(
    native, tmp_path, selected
):
    library, directory, executable = native
    origin_server, root, _, _ = certificate_fixture(tmp_path, "valid")
    if selected:
        origin_server.set_alpn_protocols([selected])
    seen_names = []
    origin_server.set_servername_callback(lambda ssl, name, ctx: seen_names.append(name))
    trust = tmp_path / "trust.pem"
    trust.write_bytes(root)
    # Reuse a fixture identity rather than claim certificate substitution proof.
    cert = (tmp_path / "origin.pem").read_bytes()
    private = (tmp_path / "private.pem").read_bytes()
    key = library.generate_ech("cover.example")
    frontend_context = TLSContext(library, (key,))
    origin_context = OriginContext(library, extra_trust=(root,), system_trust=False)
    events = []
    tasks = set()
    errors = []
    stop = asyncio.Event()

    def spawn(coroutine):
        task = asyncio.create_task(coroutine)
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    async def origin(reader, writer):
        try:
            request = await reader.readline()
            if request:
                events.append("origin-application")
                assert request == b"request\n"
                writer.write(b"origin-response\n")
                await writer.drain()
            await stop.wait()
        except Exception as exc:
            errors.append(exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, TimeoutError):
                pass

    origin_listener = await asyncio.start_server(
        lambda r, w: spawn(origin(r, w)),
        "127.0.0.1",
        0,
        ssl=origin_server,
        ssl_handshake_timeout=5,
        ssl_shutdown_timeout=1,
    )

    async def frontend(reader, writer):
        upstream = downstream = None

        async def prepare(hello):
            nonlocal upstream
            events.append("inner-hello")
            assert hello.ech_accepted
            assert hello.server_name == "origin.example"
            assert hello.protocols == (b"h2", b"http/1.1")
            upstream_reader, upstream_writer = await asyncio.open_connection(
                "127.0.0.1", origin_listener.sockets[0].getsockname()[1]
            )
            upstream, certificate = await inspect_origin(
                upstream_reader,
                upstream_writer,
                origin_context,
                hello.server_name,
                hello.protocols,
            )
            assert certificate.verified
            assert certificate.selected_alpn == (selected.encode() if selected else None)
            events.append("origin-verified")
            return FrontendIdentity((cert,), private, certificate.selected_alpn)

        try:
            downstream = await TLSStream.accept(reader, writer, frontend_context, prepare)
            events.append("frontend-complete")
            request = await downstream.read()
            # Application authorization is the explicit fixture boundary.
            # Real production policy orchestration is NOT asserted by this test.
            assert request == b"request\n"
            upstream.write(request)
            await upstream.drain()
            response = await upstream.read()
            downstream.write(response)
            await downstream.drain()
            await stop.wait()
        except Exception as exc:
            errors.append(exc)
        finally:
            if downstream:
                downstream.close()
            if upstream:
                upstream.close()

    frontend_listener = await asyncio.start_server(
        lambda r, w: spawn(frontend(r, w)), "127.0.0.1", 0
    )
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            str(executable),
            "s_client",
            "-connect",
            f"127.0.0.1:{frontend_listener.sockets[0].getsockname()[1]}",
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
        process.stdin.write(b"request\n")
        await process.stdin.drain()
        async with asyncio.timeout(5):
            assert await process.stdout.readline() == b"origin-response\n"
        assert events == [
            "inner-hello",
            "origin-verified",
            "frontend-complete",
            "origin-application",
        ]
        assert seen_names == ["origin.example"]
        assert not errors
    finally:
        frontend_listener.close()
        origin_listener.close()
        if process:
            if process.returncode is None:
                process.kill()
            await process.communicate()
        stop.set()
        await asyncio.gather(*tuple(tasks), return_exceptions=True)
        await frontend_listener.wait_closed()
        await origin_listener.wait_closed()
        frontend_context.close()
        origin_context.close()
        (tmp_path / "private.pem").unlink()
    assert not frontend_context._sessions
    assert not origin_context._sessions
