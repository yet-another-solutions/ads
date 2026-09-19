from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from msgspec.structs import replace
from sqlalchemy import select

from ads_commons.sandbox.handshake import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxRequest,
    SandboxResult,
    encode_outbound,
)
from ads_commons.security import SecurityContextHolder
from ads_sandbox_mcp.service import ExecService, Watchdog
from ads_sandbox_mcp.store import InFlight
from sandbox_support import Harness, row, wait_for_message


def start(h: Harness) -> asyncio.Task[SandboxResult]:
    with SecurityContextHolder.bound(h.identity()):
        return asyncio.create_task(h.service.execute("shell", "echo hello"))


@pytest.mark.anyio
@pytest.mark.parametrize("field", ["session_id", "message_id"])
@pytest.mark.parametrize("expired", [False, True])
async def test_acknowledge_requires_durable_correlation(
    long_harness: Harness, field: str, expired: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = long_harness
    h.publisher.mode = "none"
    if expired:
        # This test expires the row explicitly. Keep the background watchdog from
        # finishing the waiter before the cancellation assertion in cleanup.
        async def hold_watchdog(*args) -> None:
            await asyncio.Event().wait()

        monkeypatch.setattr(h.service._watchdog, "wait", hold_watchdog)
    task = start(h)
    request = await wait_for_message(h, SandboxRequest)
    assert isinstance(request, SandboxRequest)
    if expired:
        await h.service._expire(request.execution_id, h.identity().access_token, force=True)
    before = await row(h, request.execution_id)
    assert before
    ack = SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
    count = len(h.publisher.messages)
    await h.publisher.reply(replace(ack, **{field: uuid4()}))
    after = await row(h, request.execution_id)
    assert after
    assert (after.deadline, after.ack_replied, after.timed_out) == (
        before.deadline,
        before.ack_replied,
        before.timed_out,
    )
    assert len(h.publisher.messages) == count
    await h.publisher.reply(ack)
    assert isinstance(h.publisher.messages[-1], SandboxAckReset if expired else SandboxAckReply)
    if not expired:
        await h.publisher.reply(SandboxResult(request.execution_id, 0, "", "", False, 0, False))
        assert not (await task).is_error
    else:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.anyio
async def test_preack_timeout_late_ack_reset_then_unknown_ack_ignored(harness: Harness) -> None:
    h = harness
    h.publisher.mode = "none"
    result = await start(h)
    assert result.is_error and "timed out" in result.text
    saved = await row(h, result.execution_id)
    assert saved and saved.timed_out and not saved.ack_replied
    assert [type(x) for x in h.publisher.messages] == [SandboxRequest]
    await h.publisher.reply(
        SandboxAcknowledge(result.execution_id, saved.session_id, saved.message_id)
    )
    assert isinstance(h.publisher.messages[-1], SandboxAckReset)
    assert await row(h, result.execution_id) is None
    count = len(h.publisher.messages)
    await h.publisher.reply(
        SandboxAcknowledge(result.execution_id, saved.session_id, saved.message_id)
    )
    await h.publisher.reply(SandboxAcknowledge(uuid4(), uuid4(), uuid4()))
    assert len(h.publisher.messages) == count
    assert not any(isinstance(x, SandboxAbort) for x in h.publisher.messages)


@pytest.mark.anyio
async def test_postack_timeout_aborts_and_late_ack_resets(harness: Harness) -> None:
    h = harness
    h.publisher.mode = "ack"
    result = await start(h)
    assert result.is_error
    assert [type(x) for x in h.publisher.messages] == [
        SandboxRequest,
        SandboxAckReply,
        SandboxAbort,
    ]
    saved = await row(h, result.execution_id)
    assert saved and saved.timed_out and saved.ack_replied
    await h.publisher.reply(
        SandboxAcknowledge(result.execution_id, saved.session_id, saved.message_id)
    )
    assert isinstance(h.publisher.messages[-1], SandboxAckReset)
    assert await row(h, result.execution_id) is None
    tokens = [dict(headers)["authorization"] for headers in h.publisher.headers]
    assert len(set(tokens)) == 4
    assert [aud for aud, _ in h.tokens.calls] == ["ads-sandbox-manager"] * 4


@pytest.mark.anyio
async def test_ack_resets_deadline_once_and_duplicate_cannot_extend(
    long_harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = long_harness
    # Control the persisted deadline clock, not event-loop or database timing.
    # The real watchdog still polls and expires the real PostgreSQL row.
    clock = Mock(wraps=datetime)
    clock.now.return_value = datetime.now(UTC)
    monkeypatch.setattr("ads_sandbox_mcp.service.datetime", clock)
    h.publisher.mode = "none"
    task = start(h)
    request = await wait_for_message(h, SandboxRequest)
    assert isinstance(request, SandboxRequest)
    before = await row(h, request.execution_id)
    assert before
    clock.now.return_value = before.created_at + timedelta(seconds=1)
    await h.publisher.reply(
        SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
    )
    after = await row(h, request.execution_id)
    assert after and after.deadline > before.deadline
    assert (after.deadline - after.created_at).total_seconds() > h.settings.timeout_seconds
    await h.publisher.reply(
        SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
    )
    duplicate = await row(h, request.execution_id)
    assert duplicate and duplicate.deadline == after.deadline
    clock.now.return_value = before.deadline
    assert not await h.service._expire(request.execution_id, h.identity().access_token, force=False)
    assert not task.done()
    clock.now.return_value = after.deadline
    async with asyncio.timeout(5):
        result = await task
    assert result.is_error and "timed out" in result.text
    assert sum(isinstance(x, SandboxAckReply) for x in h.publisher.messages) == 1
    assert sum(isinstance(x, SandboxAbort) for x in h.publisher.messages) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("acked", [False, True])
async def test_cancel_follows_ack_boundary(harness: Harness, acked: bool) -> None:
    h = harness
    h.publisher.mode = "ack" if acked else "none"
    task = start(h)
    request = await wait_for_message(h, SandboxRequest)
    assert isinstance(request, SandboxRequest)
    if acked:
        await wait_for_message(h, SandboxAckReply)
        # Publication precedes the transaction commit; cancellation races that commit.
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    saved = await row(h, request.execution_id)
    assert saved and saved.timed_out
    assert any(isinstance(x, SandboxAbort) for x in h.publisher.messages) is acked
    await h.publisher.reply(
        SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
    )
    assert isinstance(h.publisher.messages[-1], SandboxAckReset)
    assert await row(h, request.execution_id) is None
    assert not h.service._waiters


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["ste", "insert", "publish"])
async def test_failure_before_and_after_insert(harness: Harness, failure: str) -> None:
    h = harness
    h.publisher.mode = "none"
    if failure == "ste":
        h.tokens.fail = True
    elif failure == "insert":
        h.repository.insert = AsyncMock(side_effect=RuntimeError("database unavailable"))
    else:
        h.publisher.fail = True
    began = asyncio.get_running_loop().time()
    result = await start(h)
    assert result.is_error
    elapsed = asyncio.get_running_loop().time() - began
    saved = await row(h, result.execution_id)
    if failure == "publish":
        assert elapsed >= h.settings.timeout_seconds
        assert saved and saved.timed_out
    else:
        assert "setup failed" in result.text
        assert saved is None
    assert not h.publisher.messages


@pytest.mark.anyio
async def test_manager_not_ready_is_tool_error_and_row_removed(harness: Harness) -> None:
    h = harness
    h.publisher.mode = "error"
    result = await start(h)
    assert result.is_error and result.text == "not ready"
    assert await row(h, result.execution_id) is None
    assert [type(x) for x in h.publisher.messages] == [SandboxRequest]


@pytest.mark.anyio
async def test_late_result_and_missing_id_are_eaten(harness: Harness, capsys, caplog) -> None:
    h = harness
    h.publisher.mode = "none"
    result = await start(h)
    await h.publisher.reply(
        SandboxResult(result.execution_id, 0, "secret output", "", False, 1, False)
    )
    await h.controller.on_message(b'{"type":"result"}')
    assert await row(h, result.execution_id) is not None
    captured = capsys.readouterr()
    output = captured.out + captured.err + caplog.text
    assert "result_without_waiter" in output
    assert "reply_missing_execution_id" in output
    assert "secret output" not in output


@pytest.mark.anyio
async def test_other_replica_can_ack_but_cannot_consume_result(long_harness: Harness) -> None:
    h = long_harness
    h.publisher.mode = "none"
    other = ExecService(
        h.settings, h.sessions, h.repository, h.publisher, h.tokens, Watchdog(h.settings)
    )
    from ads_sandbox_mcp.kafka import ReplyController

    controller = ReplyController(h.verifier, other)
    task = start(h)
    request = await wait_for_message(h, SandboxRequest)
    assert isinstance(request, SandboxRequest)
    headers = [("authorization", h.keys.token(azp="ads-sandbox-manager").encode())]
    await asyncio.gather(
        controller.on_message(
            encode_outbound(
                SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
            ),
            headers,
        ),
        h.publisher.reply(
            SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
        ),
    )
    assert sum(isinstance(x, SandboxAckReply) for x in h.publisher.messages) == 1
    result = SandboxResult(request.execution_id, 0, "ok", "", False, 2, False)
    await controller.on_message(encode_outbound(result), headers)
    assert not task.done() and await row(h, request.execution_id) is not None
    await h.publisher.reply(result)
    assert await task == result
    assert await row(h, request.execution_id) is None


@pytest.mark.anyio
async def test_result_commit_and_watchdog_cannot_overwrite_each_other(
    long_harness: Harness,
) -> None:
    h = long_harness
    h.publisher.mode = "none"
    task = start(h)
    request = await wait_for_message(h, SandboxRequest)
    assert isinstance(request, SandboxRequest)
    result = SandboxResult(request.execution_id, 0, "ok", "", False, 2, False)
    # Simultaneous contenders for the local completion and PostgreSQL row locks.
    await asyncio.gather(
        h.publisher.reply(result),
        h.service._expire(request.execution_id, h.identity().access_token, force=False),
    )
    assert await task == result
    assert await row(h, request.execution_id) is None


@pytest.mark.anyio
async def test_expired_duplicate_ack_does_not_suppress_abort(long_harness: Harness) -> None:
    # This test expires the row explicitly, not through a short setup deadline.
    h = long_harness
    h.publisher.mode = "ack"
    task = start(h)
    request = await wait_for_message(h, SandboxRequest)
    assert isinstance(request, SandboxRequest)
    await wait_for_message(h, SandboxAckReply)
    # Deliver the duplicate before the watchdog expires the row. A duplicate
    # arriving after that transition is a different, legitimately reset case.
    async with h.service._waiters[request.execution_id].lock:
        async with h.sessions.begin() as session:
            saved = await h.repository.locked(session, request.execution_id)
            assert saved
            saved.deadline = datetime.now(UTC) - timedelta(seconds=1)
        await h.publisher.reply(
            SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
        )
    assert (await task).is_error
    assert sum(isinstance(x, SandboxAbort) for x in h.publisher.messages) == 1
    assert not any(isinstance(x, SandboxAckReset) for x in h.publisher.messages)


@pytest.mark.anyio
async def test_schema_never_persists_tokens_payload_or_results(harness: Harness) -> None:
    assert set(InFlight.__table__.columns.keys()) == {
        "execution_id",
        "session_id",
        "message_id",
        "created_at",
        "deadline",
        "timed_out",
        "ack_replied",
    }
    harness.publisher.mode = "none"
    result = await start(harness)
    async with harness.sessions() as session:
        rows = (await session.scalars(select(InFlight))).all()
        assert len(rows) == 1 and rows[0].execution_id == result.execution_id


@pytest.mark.anyio
@pytest.mark.parametrize("failure_point", ["ack-ste", "ack-publish", "abort-publish"])
async def test_control_failure_leaves_durable_timeout(harness: Harness, failure_point: str) -> None:
    h = harness
    h.publisher.mode = "none"
    task = start(h)
    request = await wait_for_message(h, SandboxRequest)
    assert isinstance(request, SandboxRequest)
    if failure_point == "ack-ste":
        h.tokens.fail = True
    elif failure_point == "ack-publish":
        h.publisher.fail = True
    await h.publisher.reply(
        SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
    )
    if failure_point == "abort-publish":
        h.publisher.fail = True
    result = await task
    assert result.is_error and "timed out" in result.text
    saved = await row(h, request.execution_id)
    assert saved and saved.timed_out
    assert saved.ack_replied is (failure_point == "abort-publish")
    h.tokens.fail = h.publisher.fail = False
    await h.publisher.reply(
        SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
    )
    assert isinstance(h.publisher.messages[-1], SandboxAckReset)
    assert await row(h, request.execution_id) is None


@pytest.mark.anyio
async def test_database_outage_cannot_leave_http_waiter_forever(harness: Harness) -> None:
    h = harness
    h.publisher.mode = "none"
    task = start(h)
    request = await wait_for_message(h, SandboxRequest)
    assert isinstance(request, SandboxRequest)
    locked = h.repository.locked
    h.repository.locked = AsyncMock(side_effect=RuntimeError("database unavailable"))
    result = await asyncio.wait_for(task, timeout=2)
    assert result.is_error and "state unavailable" in result.text
    h.repository.locked = locked
    # Once storage recovers, the expired row still rejects late execution.
    await h.publisher.reply(
        SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
    )
    assert isinstance(h.publisher.messages[-1], SandboxAckReset)
    assert await row(h, request.execution_id) is None
