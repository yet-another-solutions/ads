from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from ads_commons.sandbox import SandboxPing, SandboxShutdown, SandboxShutdownAck, encode_inbound
from ads_sandbox_ipc.controller import PING_REQUEST_TOPIC, READY_TOPIC
from ads_sandbox_ipc.kafka import KafkaRuntime, SeekToEnd
from ipc_support import eventually


@pytest.mark.anyio
async def test_config_subscription_seeks_before_fresh_service_request_and_fans_out(
    ipc, monkeypatch
):
    from dataclasses import replace
    from uuid import UUID, uuid4

    import msgspec

    from ads_commons.egress import EGRESS_CONFIG_TOPIC, EgressConfigRequest
    from ads_sandbox_ipc.config import EgressPair
    from ipc_support import SUBJECT

    monkeypatch.setattr("ads_sandbox_ipc.kafka.AIOKafkaConsumer", FakeConsumer)
    pair = EgressPair(
        uuid4(),
        "https://egress.test",
        ("https://local.test/health", "https://peer.test/health"),
        UUID(SUBJECT),
    )
    settings = replace(ipc.settings, egress=pair)
    tokens = Mock()
    tokens.exchange_service.return_value = "fresh-service-ste"
    sent = []
    producer = SimpleNamespace(start=AsyncMock(), stop=AsyncMock())
    runtime = KafkaRuntime(settings, producer, ipc.controller, ipc.service, tokens)

    async def send(topic, **kwargs):
        assert runtime.config_consumer.started
        assert runtime.config_consumer.seeks == [(Partition(EGRESS_CONFIG_TOPIC), 11)]
        sent.append((topic, kwargs))

    producer.send_and_wait = send
    await runtime.start()
    try:
        assert len(sent) == 1 and sent[0][0] == EGRESS_CONFIG_TOPIC
        assert msgspec.json.decode(sent[0][1]["value"], type=EgressConfigRequest) == (
            EgressConfigRequest(pair.project_id, settings.sandbox_id)
        )
        assert sent[0][1]["headers"] == [("authorization", b"fresh-service-ste")]
        tokens.exchange_service.assert_called_once_with("ads")
        other = KafkaRuntime(
            replace(settings, sandbox_id=uuid4()), producer, ipc.controller, ipc.service, tokens
        )
        assert (
            other.config_consumer.options["group_id"]
            != (runtime.config_consumer.options["group_id"])
        )
    finally:
        await runtime.stop()


@dataclass(frozen=True)
class Partition:
    topic: str
    partition: int = 0


class FakeConsumer:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.topics = []
        self.listener = None
        self.started = False
        self.stopped = False
        self.paused = set()
        self.offsets = {}
        self.seeks = []
        self.records = deque()
        self.backlog_end = 11
        self.failed = False

    def subscribe(self, topics, listener):
        self.topics = topics
        self.listener = listener

    async def start(self):
        self.started = True
        await self.listener.on_partitions_assigned(self.assignment())

    async def stop(self):
        self.stopped = True

    def assignment(self):
        return {Partition(topic) for topic in self.topics}

    async def end_offsets(self, assigned):
        return {partition: self.backlog_end for partition in assigned}

    async def position(self, partition):
        return self.offsets[partition]

    def seek(self, partition, offset):
        self.seeks.append((partition, offset))
        self.offsets[partition] = offset

    def pause(self, *partitions):
        self.paused.update(partitions)

    def resume(self, *partitions):
        self.paused.difference_update(partitions)

    def __aiter__(self):
        return self

    async def __anext__(self):
        while True:
            if self.failed:
                raise RuntimeError("fake consumer failure")
            for record in list(self.records):
                partition = Partition(record.topic)
                if partition not in self.paused:
                    self.records.remove(record)
                    if record.offset < self.offsets[partition]:
                        continue
                    self.offsets[partition] = record.offset + 1
                    return record
            await asyncio.sleep(0.001)

    def feed(self, topic, value, token="", offset=11):
        self.records.append(
            SimpleNamespace(
                topic=topic, value=value, headers=[("authorization", token.encode())], offset=offset
            )
        )


@pytest.fixture
def runtime(ipc, monkeypatch):
    monkeypatch.setattr("ads_sandbox_ipc.kafka.AIOKafkaConsumer", FakeConsumer)
    producer = SimpleNamespace(start=AsyncMock(), stop=AsyncMock())
    return KafkaRuntime(ipc.settings, producer, ipc.controller, ipc.service)


@pytest.mark.anyio
async def test_seek_both_then_gate_requests_and_start_ping_only_after_ready(runtime, ipc) -> None:
    ipc.kube.ready = False
    runtime.consumer.feed(ipc.settings.request_topic, encode_inbound(ipc.request()), offset=3)
    await runtime.start()
    try:
        assert {p.topic for p, _ in runtime.consumer.seeks} == {
            ipc.settings.request_topic,
            READY_TOPIC,
        }
        assert all(offset == 11 for _, offset in runtime.consumer.seeks)
        assert not runtime.ping_consumer.started
        request = ipc.request()
        runtime.consumer.feed(ipc.settings.request_topic, encode_inbound(request), ipc.keys.token())
        await eventually(lambda: ipc.kube.polls > 1)
        assert ipc.service.current is None and not ipc.kube.calls
        ipc.kube.ready = True
        await eventually(lambda: ipc.service.current is not None)
        assert ipc.service.current.request == request  # old offset=3 ignored
        await eventually(lambda: runtime.ping_consumer.started)
        assert runtime.ping_consumer.seeks == [(Partition(PING_REQUEST_TOPIC), 11)]
        assert runtime.consumer.options == runtime.ping_consumer.options
        assert runtime.consumer.options["group_id"] == ipc.settings.group_id
        assert not runtime.consumer.options["enable_auto_commit"]
        runtime.ping_consumer.feed(PING_REQUEST_TOPIC, b"invalid", offset=11)
        from ads_commons.sandbox import encode_ping

        runtime.ping_consumer.feed(
            PING_REQUEST_TOPIC,
            encode_ping(SandboxPing(request.execution_id, ipc.settings.sandbox_id)),
            "invalid-jwt",
            offset=12,
        )
        await eventually(lambda: runtime.ping_consumer.offsets[Partition(PING_REQUEST_TOPIC)] == 13)
        assert not any(isinstance(m, SandboxPing) for m in ipc.publisher.messages)
    finally:
        await runtime.stop()
    assert runtime.consumer.stopped and runtime.ping_consumer.stopped
    runtime.producer.stop.assert_awaited_once()


@pytest.mark.anyio
async def test_runtime_polls_shutdown_during_pod_wait(runtime, ipc) -> None:
    from ads_commons.sandbox import encode_ready

    ipc.kube.pause_ready.clear()
    await runtime.start()
    try:
        await eventually(lambda: ipc.kube.polls > 0)
        runtime.consumer.feed(
            READY_TOPIC, encode_ready(SandboxShutdown(ipc.settings.sandbox_id)), ipc.keys.token()
        )
        await eventually(lambda: bool(ipc.publisher.messages))
        assert ipc.publisher.messages == [SandboxShutdownAck(ipc.settings.sandbox_id)]
        assert not runtime.ping_consumer.started
        assert not ipc.kube.calls
    finally:
        await runtime.stop()


@pytest.mark.anyio
async def test_rebalance_restores_process_position_restart_seeks_new_end() -> None:
    consumer = FakeConsumer()
    partition = Partition(READY_TOPIC)
    listener = SeekToEnd(consumer)
    await listener.on_partitions_assigned([partition])
    consumer.offsets[partition] = 18
    await listener.on_partitions_revoked([partition])
    consumer.backlog_end = 25
    await listener.on_partitions_assigned([partition])
    assert consumer.offsets[partition] == 18
    restarted = SeekToEnd(consumer)
    await restarted.on_partitions_assigned([partition])
    assert consumer.offsets[partition] == 25


@pytest.mark.anyio
async def test_runtime_closes_producer_when_consumer_start_fails(runtime) -> None:
    runtime.consumer.start = AsyncMock(side_effect=RuntimeError("fake connection failure"))
    with pytest.raises(RuntimeError):
        await runtime.start()
    runtime.producer.stop.assert_awaited_once()
    assert runtime.consumer.stopped
    assert runtime.ping_consumer.stopped


@pytest.mark.anyio
@pytest.mark.parametrize("consumer_name", ["consumer", "ping_consumer"])
async def test_dead_consumer_stops_work_and_ping(runtime, ipc, consumer_name) -> None:
    await runtime.start()
    try:
        await eventually(lambda: runtime._ping_task is not None)
        getattr(runtime, consumer_name).failed = True
        await eventually(lambda: ipc.service.failed and ipc.service.stopping)
        await eventually(lambda: runtime._ping_task is None)
        assert not ipc.service.kafka_ready
        assert ipc.service.http_ready  # HTTP readiness remains the specified latch.
        count = len(ipc.publisher.messages)
        await ipc.service.ping(SandboxPing(ipc.request().execution_id, ipc.settings.sandbox_id), "")
        assert len(ipc.publisher.messages) == count
    finally:
        await runtime.stop()


@pytest.mark.anyio
async def test_partial_ping_start_failure_closes_both_consumers(runtime, ipc) -> None:
    runtime.ping_consumer.start = AsyncMock(side_effect=RuntimeError("fake ping start failure"))
    await runtime.start()
    await eventually(lambda: ipc.service.failed)
    await runtime.stop()
    assert runtime.consumer.stopped and runtime.ping_consumer.stopped
    runtime.producer.stop.assert_awaited_once()
