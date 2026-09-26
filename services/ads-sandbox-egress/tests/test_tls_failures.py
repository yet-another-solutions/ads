import asyncio
import logging
import ssl

import pytest

from ads_sandbox_egress.origin_tls import OriginContext, inspect_origin
from ads_sandbox_egress.tls import TLSContext, UnmappableReason, UnmappableTLS
from ads_sandbox_egress.tls_transport import TLSStream
from test_tls import anyio_backend as anyio_backend
from test_tls import native as native


def test_unmappable_reason_cannot_contain_untrusted_text():
    with pytest.raises(ValueError, match="fixed"):
        UnmappableTLS("untrusted certificate/private-key text")
    for reason in UnmappableReason:
        assert str(UnmappableTLS(reason)) == reason.value


@pytest.mark.anyio
@pytest.mark.parametrize("reason", list(UnmappableReason))
async def test_unmappable_resets_actual_connection_without_repair_or_http(native, caplog, reason):
    library, _, _ = native
    context = TLSContext(library, (library.generate_ech("cover.example"),))
    origin_context = OriginContext(library, system_trust=False)
    completed = asyncio.get_running_loop().create_future()
    tasks = set()
    origin_bytes = []
    sentinel = b"untrusted-wire-value-must-never-be-logged"
    caplog.set_level(logging.WARNING, logger="ads_sandbox_egress.tls_transport")

    def spawn(coroutine):
        task = asyncio.create_task(coroutine)
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    async def bad_origin(reader, writer):
        try:
            origin_bytes.append(await reader.read(16384))
            writer.write(b"NOTLS" + sentinel)
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    origin_listener = await asyncio.start_server(
        lambda r, w: spawn(bad_origin(r, w)), "127.0.0.1", 0
    )

    async def prepare(hello):
        if reason is UnmappableReason.UPSTREAM_HANDSHAKE:
            origin_reader, origin_writer = await asyncio.open_connection(
                "127.0.0.1", origin_listener.sockets[0].getsockname()[1]
            )
            await inspect_origin(
                origin_reader, origin_writer, origin_context, hello.server_name, hello.protocols
            )
            raise AssertionError("invalid origin must not produce an identity")
        # Named external certificate-composer boundary for these two cases.
        # No success/generic-untrusted fallback is returned to TLS resume.
        raise UnmappableTLS(reason)

    async def accepted(reader, writer):
        try:
            await TLSStream.accept(reader, writer, context, prepare)
            completed.set_exception(AssertionError("must not complete frontend TLS"))
        except UnmappableTLS as exc:
            completed.set_result(exc.reason)
        except Exception as exc:
            completed.set_exception(exc)

    listener = await asyncio.start_server(lambda r, w: spawn(accepted(r, w)), "127.0.0.1", 0)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", listener.sockets[0].getsockname()[1]
    )
    try:
        client_context = ssl.create_default_context()
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_context.wrap_bio(incoming, outgoing, server_hostname="origin.example")
        with pytest.raises(ssl.SSLWantReadError):
            client.do_handshake()
        writer.write(outgoing.read())
        await writer.drain()
        async with asyncio.timeout(3):
            assert await completed is reason
            # A native TCP reset, not a synthetic response or graceful EOF.
            with pytest.raises(ConnectionResetError):
                await reader.read(16384)
        assert not context._sessions
        assert not origin_context._sessions
        if reason is UnmappableReason.UPSTREAM_HANDSHAKE:
            assert len(origin_bytes) == 1 and origin_bytes[0].startswith(b"\x16\x03")
        else:
            assert not origin_bytes
        records = [
            record for record in caplog.records if record.name == "ads_sandbox_egress.tls_transport"
        ]
        assert len(records) == 1
        assert records[0].getMessage() == f"unmappable_tls reason={reason.value}"
        assert records[0].exc_info is None
        assert sentinel.decode() not in caplog.text
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
        listener.close()
        origin_listener.close()
        await asyncio.gather(*tuple(tasks), return_exceptions=True)
        await listener.wait_closed()
        await origin_listener.wait_closed()
        context.close()
        origin_context.close()
