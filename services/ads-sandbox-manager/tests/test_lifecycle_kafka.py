import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from aiokafka.structs import TopicPartition

from ads_sandbox_manager.lifecycle_kafka import DurableAdmission

pytestmark = pytest.mark.anyio


def record(offset, topic="ads.sandbox.idle"):
    return SimpleNamespace(topic=topic, value=b"signal", key=b"session", headers=[], offset=offset)


async def test_database_failure_blocks_later_offsets_commit_retry_does_not_readmit():
    consumer, controller = AsyncMock(), AsyncMock()
    worker = DurableAdmission(consumer, controller)
    p = TopicPartition("ads.sandbox.idle", 0)
    await worker.on_partitions_assigned([p])
    order = []
    failures = 1

    async def admit(*args):
        nonlocal failures
        order.append("admit")
        if failures:
            failures -= 1
            raise RuntimeError("database unavailable")

    commits = 0

    async def commit(offsets):
        nonlocal commits
        order.append(offsets[p])
        commits += 1
        if commits == 1:
            raise RuntimeError("commit unavailable")

    controller.admit_lifecycle.side_effect = admit
    consumer.commit.side_effect = commit
    await worker.partition(p, [record(7), record(8)], worker.epochs[p])
    assert order == ["admit", "admit", 8, 8, "admit", 9]
    assert controller.admit_lifecycle.call_count == 3


async def test_rebalance_after_database_commit_fences_offset_and_replay_is_readmitted():
    consumer, controller = AsyncMock(), AsyncMock()
    worker = DurableAdmission(consumer, controller)
    p = TopicPartition("ads.sandbox.idle", 0)
    await worker.on_partitions_assigned([p])
    epoch = worker.epochs[p]

    async def admitted(*args):
        await worker.on_partitions_revoked([p])
        await worker.on_partitions_assigned([p])

    controller.admit_lifecycle.side_effect = admitted
    await worker.partition(p, [record(2), record(3)], epoch)
    consumer.commit.assert_not_called()
    assert controller.admit_lifecycle.call_count == 1
    controller.admit_lifecycle.side_effect = None
    await worker.partition(p, [record(2)], worker.epochs[p])
    consumer.commit.assert_awaited_once_with({p: 3})
    assert controller.admit_lifecycle.call_count == 2


async def test_blocked_partition_does_not_block_other_partition():
    consumer, controller = AsyncMock(), AsyncMock()
    worker = DurableAdmission(consumer, controller)
    p, q = TopicPartition("ads.sandbox.idle", 0), TopicPartition("ads.sandbox.recover", 0)
    await worker.on_partitions_assigned([p, q])
    blocked, unblock, completed = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def admit(topic, *args):
        if topic == p.topic:
            blocked.set()
            await unblock.wait()
        else:
            completed.set()

    controller.admit_lifecycle.side_effect = admit
    first = asyncio.create_task(worker.partition(p, [record(1)], worker.epochs[p]))
    await blocked.wait()
    await worker.partition(q, [record(9, q.topic)], worker.epochs[q])
    assert completed.is_set() and not first.done()
    consumer.commit.assert_awaited_once_with({q: 10})
    unblock.set()
    await first
    assert consumer.commit.call_count == 2


async def test_revoked_partition_stops_commit_retry():
    consumer, controller = AsyncMock(), AsyncMock()
    worker = DurableAdmission(consumer, controller)
    p = TopicPartition("ads.sandbox.idle", 0)
    await worker.on_partitions_assigned([p])

    async def commit(offsets):
        await worker.on_partitions_revoked([p])
        raise RuntimeError("lost assignment")

    consumer.commit.side_effect = commit
    await worker.partition(p, [record(1), record(2)], worker.epochs[p])
    assert controller.admit_lifecycle.call_count == consumer.commit.call_count == 1


async def test_poll_continues_for_new_batches_while_another_partition_is_blocked():
    consumer, controller = Mock(), AsyncMock()
    consumer.commit = AsyncMock()
    worker = DurableAdmission(consumer, controller)
    p, q = TopicPartition("ads.sandbox.idle", 0), TopicPartition("ads.sandbox.recover", 0)
    await worker.on_partitions_assigned([p, q])
    blocked, delivered, forever = asyncio.Event(), asyncio.Event(), asyncio.Event()
    polls = 0

    async def getmany(**kwargs):
        nonlocal polls
        polls += 1
        if polls == 1:
            return {p: [record(1)]}
        if polls == 2:
            await blocked.wait()
            return {q: [record(9, q.topic)]}
        await forever.wait()

    async def admit(topic, *args):
        if topic == p.topic:
            blocked.set()
            await forever.wait()
        delivered.set()

    consumer.getmany = AsyncMock(side_effect=getmany)
    controller.admit_lifecycle.side_effect = admit
    task = asyncio.create_task(worker.run())
    try:
        await asyncio.wait_for(delivered.wait(), 1)
        consumer.commit.assert_awaited_once_with({q: 10})
        consumer.pause.assert_any_call(p)
        consumer.resume.assert_called_once_with(q)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert not worker.tasks and not worker.running
