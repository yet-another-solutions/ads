"""Deterministic cross-service proof, not a live Kafka/Keycloak/Kata smoke."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import update

from ads_commons.sandbox import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxPing,
    SandboxReady,
    SandboxRequest,
    SandboxResult,
    encode_inbound,
)
from ads_commons_beans import TokenExchange
from ads_sandbox_manager.auth import IPC, MANAGER, MCP, ClientCredentials
from ads_sandbox_manager.lifecycle import (
    PING_REPLY,
    PING_REQUEST,
    RECOVER,
    LifecycleService,
    Signal,
)
from ads_sandbox_manager.lifecycle_store import LifecycleRepository
from ads_sandbox_manager.recovery import RecoveryService
from ads_sandbox_manager.service import READY_TOPIC, REPLY_TOPIC, REQUEST_TOPIC
from ads_sandbox_manager.store import SandboxSession
from ads_sandbox_mcp.store import InFlight
from handshake_support import Handshake
from ipc_support import eventually
from sandbox_fixtures import harness as mcp_harness  # noqa: F401
from sandbox_fixtures import (  # noqa: F401
    sandbox_database_url,
    sandbox_engine,
    sandbox_settings,
)
from sandbox_support import SUBJECT
from test_lifecycle import FakeCleanup
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def handshake(sessions_harness, mcp_harness, tmp_path, monkeypatch):  # noqa: F811
    mcp_harness.settings = replace(mcp_harness.settings, timeout_seconds=10)
    h = Handshake(sessions_harness, mcp_harness, tmp_path, monkeypatch)
    try:
        yield h
    finally:
        await h.close()


async def waiting_at_ack(h):
    """Deliver real request/provision/startup/ready/ack, stopping before MCP receives ack."""
    request = await h.broker.next(REQUEST_TOPIC, SandboxRequest)
    starting = h.ipc is None
    await h.deliver(request)
    if starting:
        ready = await h.broker.next(READY_TOPIC, SandboxReady)
        await h.deliver(ready)
        await eventually(lambda: h.ipc.service.kafka_ready)
    forwarded = await h.broker.next(h.ipc.settings.request_topic, SandboxRequest)
    assert forwarded.message == request.message
    await h.deliver(forwarded)
    ack = await h.broker.next(h.ipc.settings.reply_topic, SandboxAcknowledge)
    await h.deliver(ack)
    returned = await h.broker.next(REPLY_TOPIC, SandboxAcknowledge)
    assert returned.message == SandboxAcknowledge(
        request.message.execution_id, request.message.session_id, request.message.message_id
    )
    return request, returned


async def release_ack(h, ack):
    await h.deliver(ack)
    reply = await h.broker.next(REQUEST_TOPIC, SandboxAckReply)
    await h.deliver(reply)
    forwarded = await h.broker.next(h.ipc.settings.request_topic, SandboxAckReply)
    assert forwarded.message == reply.message
    await h.deliver(forwarded)
    await eventually(lambda: bool(h.ipc.store.entries()))
    return forwarded


async def result_to_http(h, task):
    result = await h.broker.next(h.ipc.settings.reply_topic, SandboxResult)
    await h.deliver(result)
    returned = await h.broker.next(REPLY_TOPIC, SandboxResult)
    assert returned.message == result.message
    await h.deliver(returned)
    response = await asyncio.wait_for(asyncio.shield(task), 5)
    assert response.status_code == 200, response.text
    assert "mcp-session-id" not in response.headers
    return response.json()["result"]


async def test_ipc_loss_recovers_fresh_disk_then_next_execution_works(handshake):
    h = handshake
    manager = h.manager
    lifecycle = LifecycleService(
        h.transit.settings,
        manager.sessions,
        LifecycleRepository(),
        FakeCleanup(manager.kube),
        h.transit.publisher,
        ClientCredentials(h.identity.settings(MANAGER), h.identity.verifier(MANAGER)),
        h.identity.exchange(MANAGER),
    )
    h.manager_controller.lifecycle = lifecycle
    h.transit.maintenance = lifecycle
    recovery = RecoveryService(
        h.transit.settings,
        manager.sessions,
        manager.repository,
        lifecycle,
        manager.service,
        manager.topics,
    )
    async with h.http() as client:
        task, _ = h.call(client, "exec_shell", "command", "printf before")
        request, ack = await waiting_at_ack(h)
        await release_ack(h, ack)
        h.ipc.finish(0, b"before")
        assert (await result_to_http(h, task))["structuredContent"]["stdout"] == "before"
        old = await row_for(manager, request.message.session_id)
        calls = len(h.ipc.kube.calls)
        await lifecycle.ping_scan()
        ping = await h.broker.next(PING_REQUEST, SandboxPing)
        assert (
            h.identity.verifier(IPC).authenticate(ping.token).subject == h.identity.client_subject
        )
        await h.deliver(ping)
        pong = await h.broker.next(PING_REPLY, SandboxPing)
        assert pong.message == ping.message
        assert pong.token != ping.token
        await h.deliver(pong)
        assert len(h.ipc.kube.calls) == calls  # IPC-alive only, not guest-alive.
        assert (await row_for(manager, old.session_id)).last_ping_at > old.last_ping_at

        await h.ipc.service.stop()  # Deterministic process-loss stand-in, not a live kill.
        async with manager.sessions.begin() as db:
            row = await db.get(SandboxSession, old.session_id)
            row.last_ping_at = datetime.now(UTC) - timedelta(seconds=40)
            row.last_ping_sent_at = None
        await lifecycle.ping_scan()
        unanswered = await h.broker.next(PING_REQUEST, SandboxPing)
        # Publication without IPC delivery, then advance the confirmed deadline.
        async with manager.sessions.begin() as db:
            from ads_sandbox_manager.store import PingProbe

            probe = await db.get(PingProbe, unanswered.message.ping_id)
            assert probe.published_at is not None
            probe.published_at = datetime.now(UTC) - timedelta(seconds=31)
            row = await db.get(SandboxSession, old.session_id)
            row.last_ping_sent_at = None
        await lifecycle.ping_scan()
        signal = await h.broker.next(RECOVER, Signal)
        assert (
            h.identity.verifier(MANAGER).authenticate(signal.token).subject
            == h.identity.client_subject
        )
        await h.manager_controller.admit_lifecycle(
            signal.topic, signal.value, signal.key, signal.headers
        )
        claimed = await row_for(manager, old.session_id)
        assert claimed.status == "recovering" and claimed.sandbox_id != old.sandbox_id
        await recovery.run_once()
        ready = await h.broker.next(READY_TOPIC, SandboxReady)
        assert ready.message.sandbox_id == claimed.sandbox_id
        await h.deliver(ready)
        await eventually(lambda: h.ipc.service.kafka_ready)
        rebuilt = await row_for(manager, old.session_id)
        assert rebuilt.status == "ready"
        assert rebuilt.pvc_id != old.pvc_id and rebuilt.pvc_uid != old.pvc_uid
        assert len(manager.kube.objects) == 4
        assert len(h.ipc.kube.calls) == 1  # Startup only; prior execution was not replayed.

        task, _ = h.call(client, "exec_python", "code", "print('after')", session_id=old.session_id)
        request, ack = await waiting_at_ack(h)
        await release_ack(h, ack)
        h.ipc.finish(0, b"after\n")
        result = await result_to_http(h, task)
        assert result["isError"] is False
        assert result["structuredContent"]["exit_code"] == 0
        assert result["structuredContent"]["stdout"] == "after\n"
        assert (await row_for(manager, old.session_id)).sandbox_id == claimed.sandbox_id
        assert h.broker.queue.empty()


async def test_shell_then_python_through_all_services_and_ack_boundary(handshake):
    h = handshake
    session_id = None
    sandbox_id = None
    disk_uid = None
    async with h.http() as client:
        for kind, argument, payload, output in [
            ("shell", "command", "printf 'shell ✓\\n'", "shell ✓\n"),
            ("python", "code", "print('python ✓')\n", "python ✓\n"),
        ]:
            start = len(h.broker.records)
            task, headers = h.call(client, f"exec_{kind}", argument, payload, session_id=session_id)
            request, ack = await waiting_at_ack(h)
            message = request.message
            assert message.kind == kind and message.payload == payload
            assert str(message.session_id) == headers["x-ads-session-id"]
            assert str(message.message_id) == headers["x-ads-message-id"]
            row = await h.mcp_row(message.execution_id)
            assert row and not row.ack_replied and not row.timed_out
            before = len(h.ipc.kube.calls)
            assert before == (1 if kind == "shell" else 2)  # startup ping, then prior exec
            assert not h.ipc.store.entries()
            assert h.ipc.service.current and not h.ipc.service.current.executing
            assert not task.done()

            # MCP publishes ack-reply, but IPC cannot execute until it receives it.
            await h.deliver(ack)
            row = await h.mcp_row(message.execution_id)
            assert row.ack_replied and row.deadline > datetime.now(UTC)
            reply = await h.broker.next(REQUEST_TOPIC, SandboxAckReply)
            await h.deliver(reply)
            forwarded = await h.broker.next(h.ipc.settings.request_topic, SandboxAckReply)
            assert forwarded.message == reply.message
            assert len(h.ipc.kube.calls) == before and not h.ipc.service.current.executing
            await h.deliver(forwarded)
            await eventually(lambda: bool(h.ipc.store.entries()))
            _, argv, stdin = h.ipc.kube.calls[-1]
            assert argv == ["ads-session-exec", kind] + ([payload] if kind == "shell" else [])
            assert stdin == (payload.encode() if kind == "python" else b"")
            assert h.ipc.store.entries()[0][0] == message.execution_id
            h.ipc.finish(0, output.encode())
            result = await result_to_http(h, task)
            assert result["isError"] is False
            data = result["structuredContent"]
            assert data["exit_code"] == 0 and data["stdout"] == output
            assert data["stderr"] == "" and data["truncated"] is False
            assert isinstance(data["duration_ms"], int) and data["duration_ms"] >= 0
            assert await h.mcp_row(message.execution_id) is None
            assert not h.ipc.store.entries() and h.ipc.kube.pid is None
            assert not h.ipc.kube.killed and h.ipc.kube.processes[-1].closed

            row = await row_for(h.manager, message.session_id)
            assert row.status == "ready" and row.last_execution_at >= row.last_ping_at
            if session_id is not None:
                assert (row.sandbox_id, row.pvc_uid) == (sandbox_id, disk_uid)
            session_id, sandbox_id, disk_uid = row.session_id, row.sandbox_id, row.pvc_uid
            assert len(h.manager.kube.objects) == 4  # same session reuses compute and PVC

            records = [r for r in h.broker.records[start:] if r.topic != READY_TOPIC]
            assert [type(r.message) for r in records] == [
                SandboxRequest,
                SandboxRequest,
                SandboxAcknowledge,
                SandboxAcknowledge,
                SandboxAckReply,
                SandboxAckReply,
                SandboxResult,
                SandboxResult,
            ]
            clients = [MCP, MANAGER, IPC, MANAGER, MCP, MANAGER, IPC, MANAGER]
            audiences = [MANAGER, IPC, MANAGER, MCP, MANAGER, IPC, MANAGER, MCP]
            exchanges = h.identity.exchanges[-8:]
            previous = headers["Authorization"].removeprefix("Bearer ")
            for record, caller, audience, exchange in zip(
                records, clients, audiences, exchanges, strict=True
            ):
                context = h.identity.verifier(audience).authenticate(record.token)
                assert context.subject == SUBJECT
                assert exchange == (caller, audience, previous, record.token)
                assert record.token != previous
                expected_key = sandbox_id if caller == IPC else session_id
                assert record.key == str(expected_key).encode()
                previous = record.token
            # Result exchange uses retained ack-reply, not any ambient HTTP context.
            assert exchanges[6][2] == records[5].token
            assert len({r.token for r in records}) == 8
        assert h.broker.queue.empty()


async def test_expired_before_ack_resets_through_manager_and_never_executes(handshake):
    h = handshake
    async with h.http() as client:
        task, _ = h.call(client, "exec_shell", "command", "must-not-run")
        request, ack = await waiting_at_ack(h)
        # Set the durable deadline directly, not an arbitrary sleep near the watchdog.
        async with h.mcp.sessions.begin() as db:
            await db.execute(
                update(InFlight)
                .where(InFlight.execution_id == request.message.execution_id)
                .values(deadline=datetime.now(UTC) - timedelta(seconds=1))
            )
        response = await asyncio.wait_for(asyncio.shield(task), 5)
        assert response.json()["result"]["isError"] is True
        assert (await h.mcp_row(request.message.execution_id)).timed_out
        await h.deliver(ack)
        reset = await h.broker.next(REQUEST_TOPIC, SandboxAckReset)
        await h.deliver(reset)
        forwarded = await h.broker.next(h.ipc.settings.request_topic, SandboxAckReset)
        assert forwarded.message == reset.message
        await h.deliver(forwarded)
        assert h.ipc.service.current is None
        assert len(h.ipc.kube.calls) == 1 and not h.ipc.kube.killed
        assert await h.mcp_row(request.message.execution_id) is None
        assert not any(isinstance(r.message, SandboxAbort) for r in h.broker.records)
        assert h.broker.queue.empty()


async def test_expired_after_ack_aborts_only_the_current_guest_execution(handshake):
    h = handshake
    async with h.http() as client:
        task, _ = h.call(client, "exec_python", "code", "while True: pass")
        request, ack = await waiting_at_ack(h)
        await release_ack(h, ack)
        pid = h.ipc.store.entries()[0][1].pid
        async with h.mcp.sessions.begin() as db:
            await db.execute(
                update(InFlight)
                .where(InFlight.execution_id == request.message.execution_id)
                .values(deadline=datetime.now(UTC) - timedelta(seconds=1))
            )
        response = await asyncio.wait_for(asyncio.shield(task), 5)
        assert response.json()["result"]["isError"] is True
        abort = await h.broker.next(REQUEST_TOPIC, SandboxAbort)
        await h.deliver(abort)
        forwarded = await h.broker.next(h.ipc.settings.request_topic, SandboxAbort)
        assert forwarded.message == abort.message
        await h.deliver(forwarded)
        result = await h.broker.next(h.ipc.settings.reply_topic, SandboxResult)
        assert result.message.is_error and result.message.text == "execution aborted"
        await h.deliver(result)
        late = await h.broker.next(REPLY_TOPIC, SandboxResult)
        await h.deliver(late)  # no live waiter; cannot resurrect a completed HTTP response
        assert h.ipc.kube.killed == [(h.ipc.kube.pod, pid)]
        assert not h.ipc.store.entries() and h.ipc.kube.pid is None
        assert (await h.mcp_row(request.message.execution_id)).timed_out
        assert not any(isinstance(r.message, SandboxAckReset) for r in h.broker.records)


@pytest.mark.parametrize("fault", ["audience", "caller", "subject", "session", "message"])
async def test_invalid_forwarded_ack_cannot_cross_execution_boundary(handshake, fault):
    h = handshake
    async with h.http() as client:
        task, _ = h.call(client, "exec_shell", "command", "printf safe")
        _, ack = await waiting_at_ack(h)
        await h.deliver(ack)
        reply = await h.broker.next(REQUEST_TOPIC, SandboxAckReply)
        await h.deliver(reply)
        valid = await h.broker.next(h.ipc.settings.request_topic, SandboxAckReply)
        broken = replace(valid)
        if fault in ("session", "message"):
            message = valid.message
            broken.value = encode_inbound(
                SandboxAckReply(
                    message.execution_id,
                    uuid4() if fault == "session" else message.session_id,
                    uuid4() if fault == "message" else message.message_id,
                )
            )
        else:
            changes = {"aud": IPC, "azp": MANAGER}
            changes.update(
                {
                    "audience": {"aud": MCP},
                    "caller": {"azp": MCP},
                    "subject": {"sub": str(uuid4())},
                }[fault]
            )
            broken.headers = [("authorization", h.identity.keys.token(**changes).encode())]
        await h.deliver(broken)
        assert len(h.ipc.kube.calls) == 1
        assert h.ipc.service.current and not h.ipc.service.current.executing
        assert not h.ipc.store.entries() and not task.done()
        await h.deliver(valid)
        await eventually(lambda: bool(h.ipc.store.entries()))
        h.ipc.finish(0, b"safe")
        assert (await result_to_http(h, task))["structuredContent"]["stdout"] == "safe"
        assert isinstance(h.transit.tokens, TokenExchange)
