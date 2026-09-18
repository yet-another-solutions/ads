from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Collection
from typing import Any
from uuid import UUID, uuid4

import msgspec
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.abc import ConsumerRebalanceListener
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import TopicAlreadyExistsError, UnknownTopicOrPartitionError, for_code

from ads_sandbox_manager.auth import ClientCredentials
from ads_sandbox_manager.barrier import GROUP, TOPIC, BarrierMessage, ManagerBarrier
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.controller import KafkaController
from ads_sandbox_manager.lifecycle import PING_REPLY, TOPICS, LifecycleService
from ads_sandbox_manager.lifecycle_kafka import DurableAdmission
from ads_sandbox_manager.recovery import RecoveryService
from ads_sandbox_manager.service import READY_TOPIC, TransitService

log = logging.getLogger(__name__)
RESPONSE_PATTERN = r"^(?:ads\.sandbox\.exec\.request|sandbox\.res\.[0-9a-f-]{36})$"


def kafka_options(settings: Settings) -> dict[str, Any]:
    context = None
    if settings.kafka_security_protocol in ("SSL", "SASL_SSL"):
        context = ssl.create_default_context(
            cafile=str(settings.kafka_ca_bundle) if settings.kafka_ca_bundle else None
        )
    return {
        "bootstrap_servers": settings.kafka_bootstrap_servers,
        "security_protocol": settings.kafka_security_protocol,
        "sasl_mechanism": settings.kafka_sasl_mechanism,
        "sasl_plain_username": settings.kafka_sasl_username,
        "sasl_plain_password": settings.kafka_sasl_password,
        "ssl_context": context,
        "request_timeout_ms": max(1, int(settings.control_seconds * 1000)),
    }


class SubscriptionReady(ConsumerRebalanceListener):  # type: ignore[misc]
    def __init__(self, consumer: AIOKafkaConsumer) -> None:
        self.consumer = consumer
        self.complete = asyncio.Event()
        self.topics: set[str] = set()
        self.seen: set[Any] = set()
        self.positions: dict[Any, int] = {}

    async def on_partitions_revoked(self, revoked: Collection[Any]) -> None:
        self.complete.clear()
        self.topics.clear()
        for partition in revoked:
            self.positions[partition] = await self.consumer.position(partition)

    async def on_partitions_assigned(self, assigned: Collection[Any]) -> None:
        # Do not skip an existing local partition's live records when a new topic joins.
        new = set(assigned) - self.seen
        if new:
            offsets = await self.consumer.end_offsets(list(new))
            for partition, offset in offsets.items():
                self.consumer.seek(partition, offset)
                self.seen.add(partition)
        for partition in assigned:
            if partition in self.positions:
                self.consumer.seek(partition, self.positions[partition])
        self.topics = set(self.consumer.subscription() or ())
        # Empty assignment still completes the subscription on a non-owning replica.
        self.complete.set()

    async def wait(self, topic: str) -> None:
        while True:
            await self.complete.wait()
            if topic in self.topics:
                return
            await asyncio.sleep(0.01)


class KafkaTransport:
    """Kafka resources only. No business handlers or detached lifecycle ownership."""

    def __init__(self, settings: Settings, credentials: ClientCredentials) -> None:
        self.settings = settings
        self.credentials = credentials
        self.replica_id = uuid4()
        options = kafka_options(settings)
        self.producer = AIOKafkaProducer(**options)
        self.admin = AIOKafkaAdminClient(**options)
        self.shared = AIOKafkaConsumer(
            **options,
            client_id=str(self.replica_id),
            group_id=GROUP,
            enable_auto_commit=False,
            auto_offset_reset="latest",
            metadata_max_age_ms=1000,
        )
        self.lifecycle = AIOKafkaConsumer(
            **options,
            group_id=f"{GROUP}-ready-{self.replica_id}",
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )
        self.coordination = AIOKafkaConsumer(
            **options,
            group_id=f"{GROUP}-barrier-{self.replica_id}",
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )
        self.maintenance = AIOKafkaConsumer(
            **options,
            group_id=f"{GROUP}-maintenance",
            enable_auto_commit=False,
            auto_offset_reset="earliest",
        )
        self.shared_seek = SubscriptionReady(self.shared)
        self.lifecycle_seek = SubscriptionReady(self.lifecycle)
        self.coordination_seek = SubscriptionReady(self.coordination)

    async def send(self, topic: str, key: UUID, raw: bytes, token: str) -> None:
        await self.producer.send_and_wait(
            topic, key=str(key).encode(), value=raw, headers=[("authorization", token.encode())]
        )

    async def broadcast(self, message: BarrierMessage) -> None:
        token = await asyncio.to_thread(self.credentials.mint)
        await self.send(TOPIC, message.sandbox_id, msgspec.json.encode(message), token)

    async def members(self) -> set[UUID]:
        # Public admin API; aiokafka 0.14 returns raw DescribeGroupsResponse tuples.
        # No private coordinator generation/member fields, and no second membership registry.
        while True:
            responses = await self.admin.describe_consumer_groups([GROUP])
            for response in responses:
                for group in response.groups:
                    error, name, state, protocol_type, _, members = group[:6]
                    if name != GROUP:
                        continue
                    if error:
                        raise for_code(error)()
                    if state == "Stable" and protocol_type == "consumer":
                        found = {UUID(member[1]) for member in members}
                        if self.replica_id in found:
                            return found
            await asyncio.sleep(0.01)

    async def subscribed(self, sandbox_id: UUID) -> None:
        await self.shared_seek.wait(f"sandbox.res.{sandbox_id}")

    async def create_topics(self, sandbox_id: UUID) -> None:
        response = await self.admin.create_topics(
            [
                NewTopic(
                    f"sandbox.{direction}.{sandbox_id}",
                    num_partitions=1,
                    replication_factor=self.settings.topic_replication_factor,
                )
                for direction in ("req", "res")
            ]
        )
        for topic_error in response.topic_errors:
            code = topic_error[1]
            if code and code != TopicAlreadyExistsError.errno:
                raise for_code(code)()


class KafkaTopics:
    def __init__(
        self, settings: Settings, transport: KafkaTransport, barrier: ManagerBarrier
    ) -> None:
        self.settings = settings
        self.transport = transport
        self.barrier = barrier

    async def prepare(self, sandbox_id: UUID) -> None:
        async with asyncio.timeout(self.settings.control_seconds):
            await self.transport.create_topics(sandbox_id)
            await self.transport.subscribed(sandbox_id)
        # Local preparation is required. Remote agreement alone is best effort.
        await self.barrier.wait(sandbox_id)

    async def remove(self, sandbox_id: UUID) -> bool:
        names = [f"sandbox.{direction}.{sandbox_id}" for direction in ("req", "res")]
        response = await self.transport.admin.delete_topics(names)
        for _, code in response.topic_error_codes:
            if code and code != UnknownTopicOrPartitionError.errno:
                raise for_code(code)()
        return not set(names).intersection(await self.transport.admin.list_topics())


class KafkaRuntime:
    def __init__(
        self,
        settings: Settings,
        transport: KafkaTransport,
        controller: KafkaController,
        service: TransitService,
        barrier: ManagerBarrier,
        lifecycle: LifecycleService,
        recovery: RecoveryService,
    ) -> None:
        self.settings = settings
        self.transport = transport
        self.controller = controller
        self.service = service
        self.barrier = barrier
        self.lifecycle = lifecycle
        self.recovery = recovery
        self._tasks: list[asyncio.Task[None]] = []
        self._startup: asyncio.Task[None] | None = None
        self._started = False

    @property
    def ready(self) -> bool:
        return self._started and all(not task.done() for task in self._tasks)

    async def start(self) -> None:
        if self._startup is None:
            self._startup = asyncio.create_task(self._start(), name="manager-kafka-start")

    async def _start(self) -> None:
        t = self.transport
        try:
            async with asyncio.timeout(self.settings.control_seconds * 4):
                await t.producer.start()
                await t.admin.start()
                # A replica advertises itself in the shared group only AFTER its broadcast
                # listeners are installed and have sought. Late join after snapshot is still
                # deliberately not fenced by the best-effort barrier.
                for consumer, seek, topics in (
                    (t.coordination, t.coordination_seek, [TOPIC]),
                    (t.lifecycle, t.lifecycle_seek, [READY_TOPIC, PING_REPLY]),
                ):
                    consumer.subscribe(topics, listener=seek)
                    await consumer.start()
                    self._tasks.append(asyncio.create_task(self._consume(consumer)))
                    await seek.complete.wait()
                t.shared.subscribe(pattern=RESPONSE_PATTERN, listener=t.shared_seek)
                await t.shared.start()
                self._tasks.append(asyncio.create_task(self._consume(t.shared)))
                await t.shared_seek.complete.wait()
                admission = DurableAdmission(t.maintenance, self.controller)
                t.maintenance.subscribe(list(TOPICS), listener=admission)
                await t.maintenance.start()
                self._tasks.append(asyncio.create_task(admission.run()))
                await self.lifecycle.start()
                await self.recovery.start()
                self._started = True
        except Exception:
            log.warning("manager Kafka startup failed")
            await self._close()

    async def _consume(self, consumer: AIOKafkaConsumer) -> None:
        try:
            async for record in consumer:
                await self.controller.on_message(
                    record.topic, record.value, record.key, record.headers
                )
        finally:
            self._started = False
            log.warning("manager Kafka consumer ended")

    async def _close(self) -> None:
        self._started = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        await self.service.stop()
        await self.lifecycle.stop()
        await self.recovery.stop()
        await self.barrier.stop()
        t = self.transport
        # Attempt every close even if one client fails.
        await asyncio.gather(
            t.shared.stop(),
            t.lifecycle.stop(),
            t.coordination.stop(),
            t.maintenance.stop(),
            t.admin.close(),
            t.producer.stop(),
            return_exceptions=True,
        )

    async def stop(self) -> None:
        if self._startup is not None:
            self._startup.cancel()
            await asyncio.gather(self._startup, return_exceptions=True)
            self._startup = None
        await self._close()
