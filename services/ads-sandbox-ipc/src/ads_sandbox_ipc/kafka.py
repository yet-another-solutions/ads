from __future__ import annotations

import asyncio
from collections.abc import Collection
from typing import Any

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.abc import ConsumerRebalanceListener

from ads_commons.sandbox import (
    SandboxAcknowledge,
    SandboxIpcError,
    SandboxPing,
    SandboxReady,
    SandboxResult,
    encode_outbound,
    encode_ping,
    encode_ready,
)
from ads_sandbox_ipc.auth import ClientCredentials, TokenMinter
from ads_sandbox_ipc.config import Settings
from ads_sandbox_ipc.controller import (
    PING_REPLY_TOPIC,
    PING_REQUEST_TOPIC,
    READY_TOPIC,
    KafkaController,
)
from ads_sandbox_ipc.service import IpcService, Outbound

log = structlog.get_logger("ads_sandbox_ipc")


class KafkaPublisher:
    def __init__(
        self,
        settings: Settings,
        producer: AIOKafkaProducer,
        tokens: TokenMinter,
        client_credentials: ClientCredentials,
    ) -> None:
        self.settings = settings
        self.producer = producer
        self.tokens = tokens
        self.client_credentials = client_credentials

    async def publish(self, message: Outbound, subject_token: str | None = None) -> None:
        token: str | None
        if isinstance(message, (SandboxReady, SandboxIpcError)):
            token = await asyncio.to_thread(self.client_credentials.mint)
        else:
            if not subject_token:
                raise ValueError("STE subject token required")
            context = await asyncio.to_thread(
                self.tokens.mint, "ads-sandbox-manager", subject_token=subject_token
            )
            token = context.access_token
            if not token:
                raise ValueError("STE returned no token")
        if isinstance(message, (SandboxAcknowledge, SandboxResult)):
            topic, raw = self.settings.reply_topic, encode_outbound(message)
        elif isinstance(message, SandboxPing):
            topic, raw = PING_REPLY_TOPIC, encode_ping(message)
        else:
            topic, raw = READY_TOPIC, encode_ready(message)
        await self.producer.send_and_wait(
            topic,
            key=str(self.settings.sandbox_id).encode(),
            value=raw,
            headers=[("authorization", token.encode())],
        )


class SeekToEnd(ConsumerRebalanceListener):  # type: ignore[misc]
    def __init__(self, consumer: AIOKafkaConsumer, paused_topic: str | None = None) -> None:
        self.consumer = consumer
        self.paused_topic = paused_topic
        self.complete = asyncio.Event()
        self.seen: set[Any] = set()
        self.positions: dict[Any, int] = {}

    async def on_partitions_revoked(self, revoked: Collection[Any]) -> None:
        for partition in revoked:
            self.positions[partition] = await self.consumer.position(partition)

    async def on_partitions_assigned(self, assigned: Collection[Any]) -> None:
        if assigned:
            offsets = await self.consumer.end_offsets(list(set(assigned) - self.seen))
            for partition, offset in offsets.items():
                self.consumer.seek(partition, offset)
                self.seen.add(partition)
            for partition in assigned:
                if partition in self.positions:
                    self.consumer.seek(partition, self.positions[partition])
                if partition.topic == self.paused_topic:
                    self.consumer.pause(partition)
            self.complete.set()


class KafkaRuntime:
    def __init__(
        self,
        settings: Settings,
        producer: AIOKafkaProducer,
        controller: KafkaController,
        service: IpcService,
    ) -> None:
        self.settings = settings
        self.producer = producer
        self.controller = controller
        self.service = service
        self.consumer = self._consumer()
        self.ping_consumer = self._consumer()
        self._tasks: list[asyncio.Task[None]] = []
        self._ping_task: asyncio.Task[None] | None = None
        self._ping_started = False

    def _consumer(self) -> AIOKafkaConsumer:
        return AIOKafkaConsumer(
            **self.settings.kafka_options(),
            group_id=self.settings.group_id,
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )

    async def start(self) -> None:
        seek = SeekToEnd(self.consumer, self.settings.request_topic)
        self.consumer.subscribe([self.settings.request_topic, READY_TOPIC], listener=seek)
        try:
            await self.producer.start()
            await self.consumer.start()
            self._tasks.append(asyncio.create_task(self._consume(self.consumer)))
            await seek.complete.wait()
            self.service.start()
            self._tasks.append(asyncio.create_task(self._gates()))
        except BaseException:
            await self.stop()
            raise

    async def _consume(self, consumer: AIOKafkaConsumer) -> None:
        try:
            async for record in consumer:
                if self.service.stopping and record.topic != READY_TOPIC:
                    continue
                # Positions advance for malformed/unauthorized/unmatched records too.
                await self.controller.on_message(record.topic, record.value, record.headers)
        except Exception:
            log.warning("ipc_consumer_failed")
        else:
            if self.service.stopping:
                return
            log.warning("ipc_consumer_ended")
        self.service.failed = True
        # Never let an independent ping loop claim that a dead request loop is alive.
        await self.service.stop()

    async def _gates(self) -> None:
        while True:
            request_partitions = [
                partition
                for partition in self.consumer.assignment()
                if partition.topic == self.settings.request_topic
            ]
            if self.service.kafka_ready and not self.service.stopping:
                self.consumer.resume(*request_partitions)
                if not self._ping_started:
                    self.ping_consumer.subscribe(
                        [PING_REQUEST_TOPIC], listener=SeekToEnd(self.ping_consumer)
                    )
                    self._ping_started = True
                    try:
                        await self.ping_consumer.start()
                    except Exception:
                        log.warning("ipc_ping_start_failed")
                        self.service.failed = True
                        await self.service.stop()
                        return
                    self._ping_task = asyncio.create_task(self._consume(self.ping_consumer))
            else:
                self.consumer.pause(*request_partitions)
            if self.service.stopping and self._ping_task is not None:
                self._ping_task.cancel()
                await asyncio.gather(self._ping_task, return_exceptions=True)
                self._ping_task = None
            await asyncio.sleep(self.settings.poll_seconds)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        if self._ping_task is not None:
            self._ping_task.cancel()
        await asyncio.gather(
            *self._tasks,
            *([self._ping_task] if self._ping_task else []),
            return_exceptions=True,
        )
        await self.service.stop()
        await self.ping_consumer.stop()
        await self.consumer.stop()
        await self.producer.stop()
