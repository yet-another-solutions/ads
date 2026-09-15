from __future__ import annotations

import asyncio
import uuid
from collections.abc import Collection
from typing import Any, Protocol

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from dishka import make_container

from ads_commons.engine import EngineOutput, encode_output
from ads_commons.security import JwtVerifier
from ads_engine.chat import ChatStreamer
from ads_engine.config import Settings, load_settings
from ads_engine.ioc import AppProvider
from ads_engine.listener import EngineListener
from ads_engine.logconfig import configure_logging
from ads_engine.service import EngineService
from ads_engine.store import ActiveSessionStore

log = structlog.get_logger("ads_engine")


class OffsetSeeker(Protocol):
    async def end_offsets(self, partitions: list[Any]) -> dict[Any, int]: ...

    def seek(self, partition: Any, offset: int) -> None: ...


class KafkaPublisher:
    def __init__(self, producer: AIOKafkaProducer, topic: str) -> None:
        self._producer = producer
        self._topic = topic

    async def publish(self, session_id: uuid.UUID, message: EngineOutput) -> None:
        await self._producer.send_and_wait(
            self._topic,
            key=str(session_id).encode("utf-8"),
            value=encode_output(message),
        )


class SeekToEndListener:
    def __init__(self, consumer: OffsetSeeker) -> None:
        self._consumer = consumer

    async def on_partitions_revoked(self, revoked: Collection[Any]) -> None:
        return None

    async def on_partitions_assigned(self, assigned: Collection[Any]) -> None:
        await seek_assigned_to_end(self._consumer, assigned)


async def seek_assigned_to_end(
    consumer: OffsetSeeker,
    assigned: Collection[Any],
) -> None:
    if not assigned:
        return
    partitions = list(assigned)
    end_offsets = await consumer.end_offsets(partitions)
    for partition, offset in end_offsets.items():
        consumer.seek(partition, offset)


async def run(settings: Settings | None = None) -> None:
    configure_logging()
    resolved = settings if settings is not None else load_settings()
    container = make_container(AppProvider(resolved))
    store = container.get(ActiveSessionStore)
    chat = container.get(ChatStreamer)
    authenticator = container.get(JwtVerifier)
    await store.reset()
    producer = AIOKafkaProducer(bootstrap_servers=resolved.kafka_bootstrap_servers)
    consumer = AIOKafkaConsumer(
        bootstrap_servers=resolved.kafka_bootstrap_servers,
        group_id=resolved.consumer_group,
        enable_auto_commit=False,
        auto_offset_reset="latest",
    )
    consumer.subscribe(
        topics=[resolved.request_topic],
        listener=SeekToEndListener(consumer),
    )
    await producer.start()
    await consumer.start()
    publisher = KafkaPublisher(producer, resolved.output_topic)
    service = EngineService(
        store=store,
        publisher=publisher,
        chat=chat,
        ping_interval_seconds=resolved.ping_interval_seconds,
        allowed_callers=resolved.allowed_callers,
    )
    listener = EngineListener(
        service=service,
        publisher=publisher,
        authenticator=authenticator,
        allowed_callers=resolved.allowed_callers,
    )
    tasks: set[asyncio.Task[None]] = set()
    log.info(
        "ads_engine_started",
        request_topic=resolved.request_topic,
        output_topic=resolved.output_topic,
    )
    try:
        async for record in consumer:
            task = asyncio.create_task(listener.on_message(record.value))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
    finally:
        for task in list(tasks):
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await consumer.stop()
        await producer.stop()
        container.close()
