import asyncio
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from aiokafka.errors import GroupAuthorizationFailedError, TopicAuthorizationFailedError
from aiokafka.protocol.admin import DescribeGroupsResponse_v3
from aiokafka.structs import TopicPartition

from ads_sandbox_manager.barrier import GROUP, TOPIC, BarrierRequest
from ads_sandbox_manager.kafka import (
    RESPONSE_PATTERN,
    KafkaRuntime,
    KafkaTopics,
    KafkaTransport,
    SubscriptionReady,
    kafka_options,
)
from ads_sandbox_manager.service import READY_TOPIC, REQUEST_TOPIC

pytestmark = pytest.mark.anyio


def consumer(**kwargs):
    c = Mock(
        start=AsyncMock(),
        stop=AsyncMock(),
        end_offsets=AsyncMock(return_value={}),
        position=AsyncMock(return_value=7),
        getmany=AsyncMock(return_value={}),
    )
    c.subscription.return_value = {REQUEST_TOPIC}
    return c


@pytest.fixture
def transport(manager_settings, monkeypatch):
    monkeypatch.setattr("ads_sandbox_manager.kafka.AIOKafkaConsumer", Mock(side_effect=consumer))
    monkeypatch.setattr(
        "ads_sandbox_manager.kafka.AIOKafkaProducer", Mock(return_value=AsyncMock())
    )
    monkeypatch.setattr(
        "ads_sandbox_manager.kafka.AIOKafkaAdminClient", Mock(return_value=AsyncMock())
    )
    return KafkaTransport(manager_settings, Mock(mint=Mock(return_value="manager-client-token")))


async def test_seek_completion_tracks_subscription_not_only_owned_partitions():
    c = consumer()
    a, b = TopicPartition(REQUEST_TOPIC, 0), TopicPartition(f"sandbox.res.{uuid4()}", 0)
    listener = SubscriptionReady(c)
    c.end_offsets.return_value = {a: 10}
    await listener.on_partitions_assigned([a])
    c.seek.assert_called_once_with(a, 10)
    await listener.on_partitions_revoked([a])
    assert not listener.complete.is_set() and not listener.topics
    c.end_offsets.return_value = {b: 20}
    c.subscription.return_value = {a.topic, b.topic}
    await listener.on_partitions_assigned([a, b])
    c.end_offsets.assert_awaited_with([b])
    assert (a, 7) in [call.args for call in c.seek.call_args_list]
    assert (b, 20) in [call.args for call in c.seek.call_args_list]
    await listener.wait(b.topic)
    await listener.on_partitions_revoked([a, b])
    await listener.on_partitions_assigned([])
    assert listener.complete.is_set()
    await listener.wait(b.topic)  # non-owner can acknowledge after its callback


async def test_subscription_wait_cannot_complete_from_stale_callback():
    c = consumer()
    listener = SubscriptionReady(c)
    await listener.on_partitions_assigned([])
    topic = f"sandbox.res.{uuid4()}"
    task = asyncio.create_task(listener.wait(topic))
    await asyncio.sleep(0)
    assert not task.done()
    await listener.on_partitions_revoked([])
    c.subscription.return_value = {REQUEST_TOPIC, topic}
    await listener.on_partitions_assigned([])
    await asyncio.wait_for(task, 1)


async def test_public_admin_membership_snapshot(transport):
    other = uuid4()
    group = (
        0,
        GROUP,
        "Stable",
        "consumer",
        "roundrobin",
        [
            ("member-a", str(transport.replica_id), "host", b"", b""),
            ("member-b", str(other), "host", b"", b""),
        ],
        0,
    )
    transport.admin.describe_consumer_groups.return_value = [
        DescribeGroupsResponse_v3(throttle_time_ms=0, groups=[group])
    ]
    assert await transport.members() == {transport.replica_id, other}
    transport.admin.describe_consumer_groups.assert_awaited_once_with([GROUP])
    bad = (30, *group[1:])
    transport.admin.describe_consumer_groups.return_value = [
        DescribeGroupsResponse_v3(throttle_time_ms=0, groups=[bad])
    ]
    with pytest.raises(GroupAuthorizationFailedError):
        await transport.members()


async def test_membership_waits_for_stable_self_inclusive_group(transport):
    group = (
        0,
        GROUP,
        "Stable",
        "consumer",
        "roundrobin",
        [("member", str(transport.replica_id), "host", b"", b"")],
    )
    transport.admin.describe_consumer_groups.side_effect = [
        [SimpleNamespace(groups=[(0, GROUP, "PreparingRebalance", "consumer", "", [])])],
        [SimpleNamespace(groups=[group])],
    ]
    assert await transport.members() == {transport.replica_id}


async def test_topic_creation_allows_only_already_exists(transport):
    sandbox = uuid4()
    transport.admin.create_topics.return_value = SimpleNamespace(
        topic_errors=[(f"sandbox.req.{sandbox}", 36, ""), (f"sandbox.res.{sandbox}", 0, "")]
    )
    await transport.create_topics(sandbox)
    topics = transport.admin.create_topics.call_args.args[0]
    assert [t.name for t in topics] == [f"sandbox.req.{sandbox}", f"sandbox.res.{sandbox}"]
    assert all(t.num_partitions == 1 and t.replication_factor == 1 for t in topics)
    transport.admin.create_topics.return_value = SimpleNamespace(
        topic_errors=[("forbidden", 29, "")]
    )
    with pytest.raises(TopicAuthorizationFailedError):
        await transport.create_topics(sandbox)


async def test_barrier_broadcast_uses_fresh_client_identity(transport):
    message = BarrierRequest(uuid4(), uuid4(), transport.replica_id, (transport.replica_id,))
    transport.credentials.mint.side_effect = ["fresh-one", "fresh-two"]
    await transport.broadcast(message)
    await transport.broadcast(message)
    calls = transport.producer.send_and_wait.call_args_list
    assert [c.kwargs["headers"] for c in calls] == [
        [("authorization", b"fresh-one")],
        [("authorization", b"fresh-two")],
    ]
    assert all(
        c.args == (TOPIC,) and c.kwargs["key"] == str(message.sandbox_id).encode() for c in calls
    )
    assert transport.credentials.mint.call_count == 2


async def test_topic_preparation_orders_local_then_remote_and_fails_local(manager_settings):
    calls = []

    async def create(_):
        calls.append("create")

    async def subscribed(_):
        calls.append("seek")

    async def barrier_wait(_):
        calls.append("barrier")

    t = SimpleNamespace(
        create_topics=AsyncMock(side_effect=create), subscribed=AsyncMock(side_effect=subscribed)
    )
    b = SimpleNamespace(wait=AsyncMock(side_effect=barrier_wait))
    topics = KafkaTopics(manager_settings, t, b)
    await topics.prepare(uuid4())
    assert calls == ["create", "seek", "barrier"]
    b.wait.reset_mock()
    t.subscribed.side_effect = TimeoutError()
    with pytest.raises(TimeoutError):
        await topics.prepare(uuid4())
    b.wait.assert_not_awaited()


async def test_sasl_tls_options_cover_every_kafka_client(manager_settings, monkeypatch):
    factories = []
    for name in ("AIOKafkaConsumer", "AIOKafkaProducer", "AIOKafkaAdminClient"):
        factory = Mock()
        monkeypatch.setattr("ads_sandbox_manager.kafka." + name, factory)
        factories.append(factory)
    settings = replace(
        manager_settings,
        kafka_security_protocol="SASL_SSL",
        kafka_sasl_username="manager",
        kafka_sasl_password="fixture-secret",
    )
    t = KafkaTransport(settings, Mock())
    options = kafka_options(settings)
    assert options["ssl_context"].check_hostname
    for factory in factories:
        for call in factory.call_args_list:
            assert call.kwargs["sasl_plain_password"] == "fixture-secret"
            assert call.kwargs["security_protocol"] == "SASL_SSL"
            assert call.kwargs["ssl_context"].check_hostname
    shared, ready, barrier, maintenance = factories[0].call_args_list
    assert maintenance.kwargs["auto_offset_reset"] == "earliest"
    assert not maintenance.kwargs["enable_auto_commit"]
    assert shared.kwargs["group_id"] == GROUP
    assert shared.kwargs["client_id"] == str(t.replica_id)
    assert ready.kwargs["group_id"] != barrier.kwargs["group_id"]
    assert all(c.kwargs["group_id"].startswith(GROUP) for c in (ready, barrier))


async def test_runtime_installs_broadcast_listeners_before_shared_group(
    transport, manager_settings
):
    t = transport
    calls = []
    gate = asyncio.Event()
    for name, c, seek in (
        ("coordination", t.coordination, t.coordination_seek),
        ("lifecycle", t.lifecycle, t.lifecycle_seek),
        ("shared", t.shared, t.shared_seek),
    ):

        async def start(name=name, seek=seek):
            calls.append(name)
            seek.complete.set()

        c.start.side_effect = start
    service, barrier = AsyncMock(), AsyncMock()
    runtime = KafkaRuntime(manager_settings, t, AsyncMock(), service, barrier, AsyncMock())

    async def consume(*args, **kwargs):
        await gate.wait()

    runtime._consume = consume
    t.maintenance.getmany.side_effect = consume
    await runtime.start()
    await runtime._startup
    assert calls == ["coordination", "lifecycle", "shared"]
    assert runtime.ready
    assert t.coordination.subscribe.call_args.args[0] == [TOPIC]
    assert t.lifecycle.subscribe.call_args.args[0] == [READY_TOPIC]
    assert t.shared.subscribe.call_args.kwargs["pattern"] == RESPONSE_PATTERN
    await runtime.stop()
    assert not runtime.ready
    for c in (t.shared, t.lifecycle, t.coordination, t.maintenance):
        c.stop.assert_awaited_once()
    t.admin.close.assert_awaited_once()
    t.producer.stop.assert_awaited_once()
    service.stop.assert_awaited_once()
    barrier.stop.assert_awaited_once()


async def test_runtime_start_failure_closes_all_resources(transport, manager_settings, caplog):
    transport.admin.start.side_effect = RuntimeError("private-token")
    runtime = KafkaRuntime(
        manager_settings, transport, AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock()
    )
    await runtime.start()
    await runtime._startup
    assert not runtime.ready
    assert "private-token" not in caplog.text
    transport.producer.stop.assert_awaited_once()
    transport.shared.stop.assert_awaited_once()
    await runtime.stop()
