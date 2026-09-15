"""Kafka is a system. The listener is the controller; business stays in one service."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Collection
from typing import Any, Protocol

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.abc import ConsumerRebalanceListener

from ads.config import Settings
from ads_commons.engine import (
    Abort,
    AckResponse,
    EngineRequest,
    authorization_headers,
    encode_abort,
    encode_ack_response,
    encode_request,
)

log = structlog.get_logger("ads.kafka")


class EngineRequests(Protocol):
    """Produce side of ``ads.engine.request``."""

    async def produce_request(self, request: EngineRequest) -> None: ...

    async def produce_ack_response(self, message: AckResponse, token: str) -> None: ...

    async def produce_abort(self, message: Abort, token: str) -> None: ...


class OffsetSeeker(Protocol):
    async def end_offsets(self, partitions: list[Any]) -> dict[Any, int]: ...

    def seek(self, partition: Any, offset: int) -> None: ...


class SeekToEndListener(ConsumerRebalanceListener):
    """On assign, skip everything already in the topic. No replay."""

    def __init__(self, consumer: OffsetSeeker) -> None:
        self._consumer = consumer

    async def on_partitions_revoked(self, revoked: Collection[Any]) -> None:
        return None

    async def on_partitions_assigned(self, assigned: Collection[Any]) -> None:
        await seek_assigned_to_end(self._consumer, assigned)


async def seek_assigned_to_end(consumer: OffsetSeeker, assigned: Collection[Any]) -> None:
    if not assigned:
        return
    partitions = list(assigned)
    end_offsets = await consumer.end_offsets(partitions)
    for partition, offset in end_offsets.items():
        consumer.seek(partition, offset)


class AiokafkaEngineRequests:
    """aiokafka producer for ``ads.engine.request``, keyed by session id."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        if self._producer is not None:
            return
        producer = AIOKafkaProducer(bootstrap_servers=self._settings.kafka_bootstrap_servers)
        await producer.start()
        self._producer = producer

    async def stop(self) -> None:
        producer = self._producer
        self._producer = None
        if producer is not None:
            await producer.stop()

    async def _send(
        self,
        session_id: uuid.UUID,
        value: bytes,
        token: str | None = None,
    ) -> None:
        await self.start()
        producer = self._producer
        if producer is None:  # pragma: no cover - start() always assigns
            raise RuntimeError("kafka producer is not started")
        headers = authorization_headers(token) if token is not None else []
        await producer.send_and_wait(
            self._settings.engine_request_topic,
            key=str(session_id).encode("utf-8"),
            value=value,
            headers=headers,
        )

    async def produce_request(self, request: EngineRequest) -> None:
        await self._send(request.session_id, encode_request(request))

    async def produce_ack_response(self, message: AckResponse, token: str) -> None:
        await self._send(message.session_id, encode_ack_response(message), token)

    async def produce_abort(self, message: Abort, token: str) -> None:
        await self._send(message.session_id, encode_abort(message), token)


class EngineOutputConsumer:
    """Consume ``ads.engine.output``, seek to end on assign, commit after the service."""

    def __init__(self, settings: Settings, on_record: Any) -> None:
        self._settings = settings
        self._on_record = on_record
        self._consumer: AIOKafkaConsumer | None = None
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        consumer = AIOKafkaConsumer(
            bootstrap_servers=self._settings.kafka_bootstrap_servers,
            group_id=self._settings.engine_consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )
        consumer.subscribe(
            topics=[self._settings.engine_output_topic],
            listener=SeekToEndListener(consumer),
        )
        await consumer.start()
        self._consumer = consumer
        self._task = asyncio.create_task(self._loop(consumer))

    async def stop(self) -> None:
        task, consumer = self._task, self._consumer
        self._task, self._consumer = None, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        if consumer is not None:
            await consumer.stop()

    async def _loop(self, consumer: AIOKafkaConsumer) -> None:
        log.info("ads_engine_output_consumer_started", topic=self._settings.engine_output_topic)
        async for record in consumer:
            try:
                await self._on_record(record.value, record.headers)
            except Exception as exc:  # do not commit a failed unit of work
                log.warning("engine_output_failed", error=str(exc))
                continue
            await consumer.commit()
