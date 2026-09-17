import asyncio
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from ads_sandbox_manager.barrier import BarrierAck, BarrierRequest, ManagerBarrier

pytestmark = pytest.mark.anyio


async def until(predicate):
    async with asyncio.timeout(2):
        while not predicate():
            await asyncio.sleep(0.001)


def peer(settings):
    port = SimpleNamespace(
        replica_id=uuid4(), members=AsyncMock(), subscribed=AsyncMock(), broadcast=AsyncMock()
    )
    return ManagerBarrier(settings, port)


async def test_two_replica_barrier_waits_for_subscription(manager_settings):
    a, b = peer(manager_settings), peer(manager_settings)
    members = {a.port.replica_id, b.port.replica_id}
    a.port.members.return_value = members
    gate = asyncio.Event()

    async def subscribed(_):
        await gate.wait()

    b.port.subscribed.side_effect = subscribed
    a.port.broadcast.side_effect = b.accept
    b.port.broadcast.side_effect = a.accept
    task = asyncio.create_task(a.wait(uuid4()))
    try:
        await until(lambda: b.port.subscribed.called)
        assert not task.done()
        gate.set()
        await task
        assert b.port.broadcast.await_count == 1
        assert not a.rounds
    finally:
        await a.stop()
        await b.stop()


async def test_snapshot_unknown_size_single_and_multiple_members(manager_settings):
    for count in (1, 2, 5):
        peers = [peer(manager_settings) for _ in range(count)]
        members = {p.port.replica_id for p in peers}

        async def broadcast(message, peers=peers):
            for p in peers:
                await p.accept(message)

        for p in peers:
            p.port.members.return_value = members
            p.port.broadcast.side_effect = broadcast
        try:
            await asyncio.gather(*(p.wait(uuid4()) for p in peers))
            assert all(not p.rounds for p in peers)
        finally:
            for p in peers:
                await p.stop()


@pytest.mark.parametrize("failure", ["missing", "discovery", "publish", "discovery-timeout"])
async def test_best_effort_warns_and_proceeds(manager_settings, caplog, failure):
    a = peer(replace(manager_settings, barrier_seconds=0.03))
    absent = uuid4()
    a.port.members.return_value = {a.port.replica_id, absent}
    if failure == "discovery":
        a.port.members.side_effect = RuntimeError("private-token")
    elif failure == "publish":
        a.port.broadcast.side_effect = RuntimeError("private-token")
    elif failure == "discovery-timeout":
        a.port.members.side_effect = asyncio.Event().wait
    await asyncio.wait_for(a.wait(uuid4()), 1)
    assert "proceeding" in caplog.text
    assert "private-token" not in caplog.text
    if failure in ("missing", "publish"):
        assert str(absent) in caplog.text
    assert not a.rounds


async def test_ack_requires_round_sandbox_initiator_and_snapshot_member(manager_settings):
    a = peer(manager_settings)
    member, sandbox = uuid4(), uuid4()
    a.port.members.return_value = {a.port.replica_id, member}
    task = asyncio.create_task(a.wait(sandbox))
    await until(lambda: a.port.broadcast.called)
    request = a.port.broadcast.call_args.args[0]
    valid = BarrierAck(request.barrier_id, sandbox, a.port.replica_id, member)
    from msgspec.structs import replace as change

    for field in ("barrier_id", "sandbox_id", "initiator", "member"):
        await a.accept(change(valid, **{field: uuid4()}))
        assert not task.done()
    await a.accept(valid)
    await a.accept(valid)
    await task
    await a.accept(valid)  # delayed ack after cleanup cannot complete any future round
    assert not a.rounds


async def test_participant_timeout_duplicates_and_shutdown_are_bounded(manager_settings, caplog):
    b = peer(replace(manager_settings, barrier_seconds=0.03))
    initiator = uuid4()
    request = BarrierRequest(uuid4(), uuid4(), initiator, (initiator, b.port.replica_id))
    gate = asyncio.Event()

    async def blocked(_):
        await gate.wait()

    b.port.subscribed.side_effect = blocked
    await b.accept(request)
    await b.accept(request)
    assert len(b.participants) == 1
    await until(lambda: not b.participants)
    b.port.broadcast.assert_not_awaited()
    assert "acknowledgement unavailable" in caplog.text
    await b.accept(request)
    await b.stop()
    assert not b.participants


async def test_cancellation_not_converted_to_proceed(manager_settings, caplog):
    a = peer(manager_settings)
    a.port.members.side_effect = asyncio.Event().wait
    task = asyncio.create_task(a.wait(uuid4()))
    await until(lambda: a.port.members.called)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert "proceeding" not in caplog.text
    assert not a.rounds


async def test_late_joiner_is_not_part_of_snapshot(manager_settings):
    a = peer(manager_settings)
    a.port.members.return_value = {a.port.replica_id}
    late = peer(manager_settings)

    async def broadcast(message):
        # Replica appears after membership was captured; it cannot extend this round.
        await late.accept(message)

    a.port.broadcast.side_effect = broadcast
    await a.wait(uuid4())
    late.port.subscribed.assert_not_awaited()
    assert not late.participants
