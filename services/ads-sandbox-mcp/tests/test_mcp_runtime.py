from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from sqlalchemy import text

from ads_commons.sandbox.handshake import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxRequest,
    encode_outbound,
)
from ads_commons.security import SecurityContextHolder
from ads_sandbox_mcp.kafka import KafkaPublisher, KafkaRuntime, SeekToEnd, consumer_group
from ads_sandbox_mcp.scheduler import GC_LOCK, ClusterScheduler
from ads_sandbox_mcp.store import InFlight
from sandbox_support import Harness, row, rpc, wait_for_message

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("acked", [False, True])
async def test_real_sdk_http_disconnect_tombstones(long_harness: Harness, acked: bool) -> None:
    h = long_harness
    h.publisher.mode = "ack" if acked else "none"
    app = h.app()
    incoming: asyncio.Queue[dict] = asyncio.Queue()
    sent: list[dict] = []
    headers = {
        **h.headers("tools/call", "exec_shell"),
        "host": "testserver.local",
        "content-type": "application/json",
    }
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver.local", 443),
    }

    async def send(message: dict) -> None:
        sent.append(message)

    await incoming.put(
        {
            "type": "http.request",
            "body": json.dumps(
                rpc("tools/call", name="exec_shell", arguments={"command": "sleep 60"})
            ).encode(),
            "more_body": False,
        }
    )
    async with app.lifespan():
        task = asyncio.create_task(app(scope, incoming.get, send))
        request = await wait_for_message(h, SandboxRequest)
        assert isinstance(request, SandboxRequest)
        if acked:
            await wait_for_message(h, SandboxAckReply)
        began = asyncio.get_running_loop().time()
        await incoming.put({"type": "http.disconnect"})
        await asyncio.wait_for(task, timeout=5)
        assert asyncio.get_running_loop().time() - began < h.settings.timeout_seconds / 2
        saved = await row(h, request.execution_id)
        assert saved and saved.timed_out
        assert any(isinstance(x, SandboxAbort) for x in h.publisher.messages) is acked
        assert not h.service._waiters
    assert not any(x.get("status") == 200 for x in sent)


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "ads"},
        {"azp": "ads-engine"},
        {"azp": None},
        {"iss": "https://wrong.test"},
        {"exp": 1},
        {"sub": "not-a-uuid"},
    ],
)
async def test_kafka_rejects_invalid_identity(harness: Harness, claims: dict) -> None:
    h = harness
    h.service.accept_reply = AsyncMock()
    message = encode_outbound(SandboxAcknowledge(uuid4(), uuid4(), uuid4()))
    token = (
        h.keys.token(azp="ads-sandbox-manager", **{k: v for k, v in claims.items() if k != "azp"})
        if "azp" not in claims
        else h.keys.token(**claims)
    )
    await h.controller.on_message(message, [("authorization", token.encode())])
    h.service.accept_reply.assert_not_awaited()


@pytest.mark.parametrize(
    "headers", [None, [], [("authorization", None)], [("authorization", b"garbage")]]
)
async def test_kafka_missing_or_malformed_auth(harness: Harness, headers) -> None:
    h = harness
    h.service.accept_reply = AsyncMock()
    await h.controller.on_message(
        encode_outbound(SandboxAcknowledge(uuid4(), uuid4(), uuid4())), headers
    )
    h.service.accept_reply.assert_not_awaited()


async def test_reply_verification_does_not_bind_or_replace_http_identity(harness: Harness) -> None:
    h = harness
    original = h.identity()
    observed = []

    async def capture(reply) -> None:
        observed.append(SecurityContextHolder.require())
        assert reply.subject_token != original.access_token

    h.service.accept_reply = capture
    with SecurityContextHolder.bound(original):
        await h.publisher.reply(SandboxAcknowledge(uuid4(), uuid4(), uuid4()))
        assert SecurityContextHolder.require() is original
    assert observed == [original]


async def test_malformed_authorized_reply_never_reaches_service(harness: Harness) -> None:
    h = harness
    h.service.accept_reply = AsyncMock()
    headers = [("authorization", h.keys.token(azp="ads-sandbox-manager").encode())]
    for raw in (
        b"invalid JSON",
        json.dumps({"type": "result", "execution_id": str(uuid4())}).encode(),
        json.dumps({"type": "ping", "execution_id": str(uuid4())}).encode(),
    ):
        await h.controller.on_message(raw, headers)
    h.service.accept_reply.assert_not_awaited()


async def test_publisher_topics_keys_headers_and_consumer_seek(harness: Harness) -> None:
    h = harness
    producer = Mock(send_and_wait=AsyncMock())
    publisher = KafkaPublisher(producer, h.settings)
    message = SandboxRequest(uuid4(), uuid4(), uuid4(), "python", "print(1)")
    headers = [("authorization", b"test-token")]
    await publisher.publish(message, headers, session_id=message.session_id)
    args, kwargs = producer.send_and_wait.call_args
    assert args == ("ads.sandbox.exec.request",)
    assert kwargs["key"] == str(message.session_id).encode()
    assert kwargs["headers"] == headers
    assert b"print(1)" in kwargs["value"]
    consumer = Mock(end_offsets=AsyncMock(return_value={"partition": 42}))
    listener = SeekToEnd(consumer)
    await listener.on_partitions_revoked(["partition"])
    await listener.on_partitions_assigned(["partition"])
    consumer.seek.assert_called_once_with("partition", 42)
    await listener.on_partitions_assigned([])
    consumer.end_offsets.assert_awaited_once()
    assert len({consumer_group() for _ in range(100)}) == 100


async def test_kafka_runtime_start_stop_and_failure(harness: Harness) -> None:
    h = harness
    producer = Mock(start=AsyncMock(), stop=AsyncMock())
    consumer = Mock(start=AsyncMock(), stop=AsyncMock())
    runtime = KafkaRuntime(h.settings, producer, consumer, h.controller)
    blocked = asyncio.Event()
    runtime._consume = blocked.wait
    assert not runtime.ready()
    await runtime.start()
    assert runtime.ready()
    assert consumer.subscribe.call_args.args[0] == ["ads.sandbox.exec.reply"]
    assert isinstance(consumer.subscribe.call_args.kwargs["listener"], SeekToEnd)
    await runtime.stop()
    assert not runtime.ready()
    producer.stop.assert_awaited_once()
    consumer.stop.assert_awaited_once()
    consumer.start.side_effect = RuntimeError("broker unavailable")
    with pytest.raises(RuntimeError):
        await runtime.start()
    assert producer.stop.await_count == 2


async def test_gc_age_not_deadline_and_advisory_leader_exclusion(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = harness
    now = datetime.now(UTC)
    # Keep DB/runner latency out of the short fixture's retention-age boundary.
    # Advisory locking, scheduler sleeps and PostgreSQL collection remain real.
    clock = Mock(wraps=datetime)
    clock.now.return_value = now
    monkeypatch.setattr("ads_sandbox_mcp.scheduler.datetime", clock)
    old, recent = uuid4(), uuid4()
    async with h.sessions.begin() as session:
        for execution_id, created_at in [(old, now - timedelta(seconds=10)), (recent, now)]:
            await h.repository.insert(
                session,
                InFlight(
                    execution_id=execution_id,
                    session_id=uuid4(),
                    message_id=uuid4(),
                    created_at=created_at,
                    deadline=now - timedelta(seconds=1),
                    timed_out=True,
                    ack_replied=False,
                ),
            )
    scheduler = ClusterScheduler(h.engine, h.repository, h.settings)
    async with h.engine.connect() as leader, h.engine.connect() as contender:
        assert await leader.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": GC_LOCK})
        assert not await contender.scalar(
            text("SELECT pg_try_advisory_lock(:key)"), {"key": GC_LOCK}
        )
        await scheduler.start()
        await asyncio.sleep(h.settings.timeout_seconds * 1.2)
        assert await row(h, old) is not None
        await leader.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": GC_LOCK})
        await leader.commit()
        await scheduler.stop()
    async with h.sessions.begin() as session:
        await scheduler.tick(session)
    assert await row(h, old) is None
    assert await row(h, recent) is not None
    clock.now.return_value = now + timedelta(seconds=2 * h.settings.timeout_seconds)
    async with h.sessions.begin() as session:
        await scheduler.tick(session)
    assert await row(h, recent) is not None  # Strict creation-age cutoff, not deadline.
    clock.now.return_value += timedelta(microseconds=1)
    # Stopping the actual leader releases its session lock (not a transaction lock).
    await scheduler.start()
    async with asyncio.timeout(5):
        while await row(h, recent) is not None:
            await asyncio.sleep(0.1)
    await scheduler.stop()
    async with h.engine.connect() as connection:
        assert await connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": GC_LOCK})
        await connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": GC_LOCK})
        await connection.commit()
