import asyncio
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs
from uuid import uuid4

import pytest
from sqlalchemy import update

from ads_commons.sandbox import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxRequest,
    SandboxResult,
    decode_inbound,
    decode_outbound,
    encode_inbound,
    encode_outbound,
)
from ads_commons.security import SecurityContextHolder
from ads_commons_beans import TokenExchange, TokenExchangeSettings
from ads_sandbox_manager.auth import IPC, MANAGER, MCP
from ads_sandbox_manager.controller import KafkaController
from ads_sandbox_manager.service import REPLY_TOPIC, REQUEST_TOPIC, TransitService, VerifiedExec
from ads_sandbox_manager.store import SandboxSession
from test_manager_security import keys  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, seed, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def until(predicate):
    async with asyncio.timeout(3):
        while not await predicate():
            await asyncio.sleep(0.005)


class Tokens:
    def __init__(self):
        self.calls = []

    def mint(self, audience, subject_token=None):
        assert subject_token
        self.calls.append((audience, subject_token))
        return SimpleNamespace(access_token=f"fresh-{len(self.calls)}")


def transit(h, **settings):
    return TransitService(
        replace(h.settings, ready_seconds=2, control_seconds=1, **settings),
        h.sessions,
        h.repository,
        h.service,
        AsyncMock(),
        Tokens(),
        AsyncMock(),
    )


def request():
    return SandboxRequest(uuid4(), uuid4(), uuid4(), "shell", "echo hello")


async def test_request_provisions_waits_for_ipc_ready_and_transits_result(sessions_harness):  # noqa: F811
    h = sessions_harness
    service, message = transit(h), request()
    try:
        await service.accept(VerifiedExec(message.session_id, message, "subject", "mcp-token"))

        async def created():
            row = await row_for(h, message.session_id)
            return row and row.ipc_deployment_uid

        await until(created)
        row = await row_for(h, message.session_id)
        assert row.status == "creating"
        service.publisher.send.assert_not_awaited()
        await service.ready(row.sandbox_id)

        async def forwarded():
            return service.publisher.send.called

        await until(forwarded)
        call = service.publisher.send.call_args
        assert call.args[:2] == (f"sandbox.req.{row.sandbox_id}", message.session_id)
        assert decode_inbound(call.args[2]) == message
        assert call.args[3] == "fresh-1"
        ack = SandboxAcknowledge(message.execution_id, message.session_id, message.message_id)
        await service.reply(row.sandbox_id, ack, "ipc-ack-token")
        result = SandboxResult(message.execution_id, 0, "hello", "", False, 1, False)
        await service.reply(row.sandbox_id, result, "ipc-result-token")
        assert service.tokens.calls == [
            (IPC, "mcp-token"),
            (MCP, "ipc-ack-token"),
            (MCP, "ipc-result-token"),
        ]
        assert service.publisher.send.call_args.args[:2] == (REPLY_TOPIC, message.session_id)
        assert decode_outbound(service.publisher.send.call_args.args[2]) == result
        saved = await row_for(h, message.session_id)
        assert saved.status == "ready" and saved.last_ping_at is not None
        assert saved.last_execution_at >= saved.last_ping_at
        assert SecurityContextHolder.get() is None
    finally:
        await service.stop()


@pytest.mark.parametrize("control", [SandboxAbort, SandboxAckReset])
async def test_reset_drops_buffer_but_does_not_cancel_claimed_worker(sessions_harness, control):  # noqa: F811
    h = sessions_harness
    service, message = transit(h), request()
    gate, entered = asyncio.Event(), asyncio.Event()

    async def topics(_):
        entered.set()
        await gate.wait()

    h.topics.hook = topics
    try:
        await service.accept(VerifiedExec(message.session_id, message, "subject", "request-token"))
        await asyncio.wait_for(entered.wait(), 3)
        reset = control(message.execution_id, message.session_id, message.message_id)
        await service.accept(VerifiedExec(message.session_id, reset, "subject", "control-token"))
        assert message.execution_id not in service._pending
        assert not service._workers[message.session_id].done()
        gate.set()

        async def created():
            row = await row_for(h, message.session_id)
            return row and row.ipc_deployment_uid

        await until(created)
        row = await row_for(h, message.session_id)
        await service.ready(row.sandbox_id)
        assert len(h.kube.objects) == 4
        assert all(
            not isinstance(decode_inbound(c.args[2]), SandboxRequest)
            for c in service.publisher.send.call_args_list
        )
    finally:
        await service.stop()


@pytest.mark.parametrize("status", ["pending", "creating", "shutting_down", "failed", "recovering"])
async def test_initial_status_wait_times_out_without_provisioning(sessions_harness, status):  # noqa: F811
    h, message = sessions_harness, request()
    await seed(h, message.session_id, status)
    service = transit(h)
    service.settings = replace(service.settings, ready_seconds=0.05)
    service.provisioner = AsyncMock()
    try:
        await service.accept(VerifiedExec(message.session_id, message, "subject", "token"))
        await service._requests[message.execution_id]
        service.provisioner.provision.assert_not_awaited()
        error = decode_outbound(service.publisher.send.call_args.args[2])
        assert error.is_error and error.execution_id == message.execution_id
        assert not service._pending
    finally:
        await service.stop()


async def test_ready_is_durable_idempotent_without_waiter_and_needs_uids(sessions_harness, caplog):  # noqa: F811
    h, message = sessions_harness, request()
    service = transit(h)
    row = await seed(h, message.session_id, "creating")
    waiter = asyncio.create_task(service.ready(row.sandbox_id))
    await asyncio.sleep(0.02)
    assert not waiter.done()
    async with h.sessions.begin() as db:
        await db.execute(
            update(SandboxSession)
            .where(SandboxSession.session_id == message.session_id)
            .values(
                pvc_uid="disk",
                ipc_pvc_uid="ipc-disk",
                guest_deployment_uid="guest",
                ipc_deployment_uid="ipc",
            )
        )
    await waiter
    before = await row_for(h, message.session_id)
    await service.ready(row.sandbox_id)
    after = await row_for(h, message.session_id)
    assert before.status == after.status == "ready"
    assert before.last_execution_at == after.last_execution_at
    assert "duplicate IPC ready" in caplog.text
    await service.ready(uuid4())


@pytest.mark.parametrize("status", ["creating", "shutting_down", "stopped", "failed", "recovering"])
async def test_results_forward_and_stamp_regardless_of_status(sessions_harness, status):  # noqa: F811
    h, message = sessions_harness, request()
    row = await seed(h, message.session_id, status)
    old = datetime.now(UTC) - timedelta(days=1)
    async with h.sessions.begin() as db:
        await db.execute(update(SandboxSession).values(last_execution_at=old))
    service = transit(h)
    result = SandboxResult(message.execution_id, 0, "output", "", False, 2, False)
    await service.reply(row.sandbox_id, result, "ipc-token")
    assert decode_outbound(service.publisher.send.call_args.args[2]) == result
    saved = await row_for(h, message.session_id)
    assert saved.status == status and saved.last_execution_at > old
    before = service.publisher.send.await_count
    await service.reply(uuid4(), result, "ipc-token")
    assert service.publisher.send.await_count == before


async def test_reset_during_ste_does_not_forward_dropped_request(sessions_harness):  # noqa: F811
    h, message = sessions_harness, request()
    await seed(h, message.session_id, "ready")
    service = transit(h)
    entered, gate = threading.Event(), threading.Event()
    mint = service.tokens.mint

    def slow(audience, subject_token):
        if subject_token == "request-token":
            entered.set()
            assert gate.wait(3)
        return mint(audience, subject_token)

    service.tokens.mint = slow
    try:
        await service.accept(VerifiedExec(message.session_id, message, "subject", "request-token"))
        assert await asyncio.to_thread(entered.wait, 2)
        control = SandboxAbort(message.execution_id, message.session_id, message.message_id)
        await service.accept(VerifiedExec(message.session_id, control, "subject", "abort-token"))
        task = service._requests[message.execution_id]
        gate.set()
        await task
        calls = service.publisher.send.call_args_list
        assert len(calls) == 1 and decode_inbound(calls[0].args[2]) == control
    finally:
        gate.set()
        await service.stop()


async def test_reset_before_claim_does_not_start_worker(sessions_harness):  # noqa: F811
    h, message = sessions_harness, request()
    service = transit(h)
    entered, gate = asyncio.Event(), asyncio.Event()

    async def first_read(_):
        if not entered.is_set():
            entered.set()
            await gate.wait()
        return None

    service._row = first_read
    service.provisioner = AsyncMock()
    await service.accept(VerifiedExec(message.session_id, message, "subject", "request-token"))
    await entered.wait()
    task = service._requests[message.execution_id]
    control = SandboxAckReset(message.execution_id, message.session_id, message.message_id)
    await service.accept(VerifiedExec(message.session_id, control, "subject", "reset-token"))
    gate.set()
    await task
    service.provisioner.provision.assert_not_awaited()
    service.publisher.send.assert_not_awaited()
    await service.stop()


async def test_signed_transit_handshake_with_real_ste_adapter(sessions_harness, keys, monkeypatch):  # noqa: F811
    h, message = sessions_harness, request()
    row = await seed(h, message.session_id, "ready")
    service = transit(h)
    exchanges = []

    def endpoint(request, **kwargs):
        body = parse_qs(request.data.decode())
        assert body["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
        assert body["client_id"] == [MANAGER]
        assert "refresh_token" not in body
        exchanges.append(body)
        token = keys.token(aud=body["audience"][0], azp=MANAGER)
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        import json

        response.read.return_value = json.dumps({"access_token": token}).encode()
        return response

    monkeypatch.setattr("ads_commons_beans.token_exchange.urlopen", endpoint)
    service.tokens = TokenExchange(
        TokenExchangeSettings("https://identity.test/token", MANAGER, "fixture", None),
        keys.verifier,
    )
    controller = KafkaController(service.settings, keys.verifier, service, AsyncMock(), AsyncMock())
    mcp_token, ipc_token = keys.token(azp=MCP), keys.token(azp=IPC)

    async def deliver(topic, value, key, token):
        await controller.on_message(
            topic, value, str(key).encode(), [("authorization", token.encode())]
        )

    try:
        await deliver(REQUEST_TOPIC, encode_inbound(message), message.session_id, mcp_token)
        await service._requests[message.execution_id]
        ack = SandboxAcknowledge(message.execution_id, message.session_id, message.message_id)
        await deliver(
            f"sandbox.res.{row.sandbox_id}", encode_outbound(ack), row.sandbox_id, ipc_token
        )
        followup = SandboxAckReply(message.execution_id, message.session_id, message.message_id)
        await deliver(REQUEST_TOPIC, encode_inbound(followup), message.session_id, mcp_token)
        result = SandboxResult(message.execution_id, 0, "hello", "", False, 1, False)
        await deliver(
            f"sandbox.res.{row.sandbox_id}", encode_outbound(result), row.sandbox_id, ipc_token
        )
        assert [b["audience"][0] for b in exchanges] == [IPC, MCP, IPC, MCP]
        assert [b["subject_token"][0] for b in exchanges] == [
            mcp_token,
            ipc_token,
            mcp_token,
            ipc_token,
        ]
        calls = service.publisher.send.call_args_list
        assert len(calls) == 4
        minted = [c.args[3] for c in calls]
        assert len(set(minted)) == 4 and mcp_token not in minted and ipc_token not in minted
        for token, audience in zip(minted, [IPC, MCP, IPC, MCP], strict=True):
            verified = keys.verifier.authenticate(token, audience=audience)
            assert verified.subject == keys.subject
        assert decode_inbound(calls[0].args[2]) == message
        assert decode_outbound(calls[1].args[2]) == ack
        assert decode_inbound(calls[2].args[2]) == followup
        assert decode_outbound(calls[3].args[2]) == result
        assert SecurityContextHolder.get() is None
    finally:
        await service.stop()
