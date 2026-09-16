from __future__ import annotations

import asyncio

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from dishka import make_container

from ads_commons_beans import CommonsBeansProvider
from ads_commons_schema import alembic_ini_for, mapped_tables, prepare_schema
from ads_engine.config import Settings, load_settings
from ads_engine.ioc import AppProvider
from ads_engine.kafka import SeekToEndListener
from ads_engine.listener import EngineListener
from ads_engine.logconfig import configure_logging
from ads_engine.store import ActiveSessionRow, ActiveSessionStore

log = structlog.get_logger("ads_engine")


async def run(settings: Settings | None = None) -> None:
    configure_logging()
    resolved = settings if settings is not None else load_settings()
    prepare_schema(
        alembic_ini=alembic_ini_for("ads-engine"),
        database_url=resolved.database_url,
        tables=mapped_tables(ActiveSessionRow),
    )
    configure_logging()
    container = make_container(CommonsBeansProvider(), AppProvider(resolved))
    store = container.get(ActiveSessionStore)
    await store.reset()
    producer = container.get(AIOKafkaProducer)
    consumer = container.get(AIOKafkaConsumer)
    seek_to_end_listener = container.get(SeekToEndListener)
    consumer.subscribe(
        topics=[resolved.request_topic],
        listener=seek_to_end_listener,
    )
    log.info(
        "ads_engine_kafka_starting",
        bootstrap_servers=resolved.kafka_bootstrap_servers,
        request_topic=resolved.request_topic,
        consumer_group=resolved.consumer_group,
    )
    await producer.start()
    await consumer.start()
    listener = container.get(EngineListener)
    tasks: set[asyncio.Task[None]] = set()
    log.info(
        "ads_engine_started",
        request_topic=resolved.request_topic,
        output_topic=resolved.output_topic,
    )
    try:
        async for record in consumer:
            task = asyncio.create_task(listener.on_message(record.value, record.headers))
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
