from __future__ import annotations

import asyncio

import pytest
from aiokafka import AIOKafkaConsumer
from aiokafka.abc import ConsumerRebalanceListener
from dishka import make_container

from ads_commons_beans import CommonsBeansProvider
from ads_engine import ioc
from ads_engine.config import Settings
from ads_engine.ioc import AppProvider
from ads_engine.kafka import SeekToEndListener, seek_assigned_to_end


class FakeConsumer:
    def __init__(self, ends: dict[object, int]) -> None:
        self._ends = ends
        self.seeks: list[tuple[object, int]] = []

    async def end_offsets(self, partitions: list[object]) -> dict[object, int]:
        return {partition: self._ends[partition] for partition in partitions}

    def seek(self, partition: object, offset: int) -> None:
        self.seeks.append((partition, offset))


def test_provider_constructs_consumer_and_seek_listener(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consumer = FakeConsumer({("ads.engine.request", 0): 4})
    constructor_options: dict[str, object] = {}

    def make_consumer(**options: object) -> FakeConsumer:
        constructor_options.update(options)
        return consumer

    monkeypatch.setattr(ioc, "AIOKafkaConsumer", make_consumer)
    container = make_container(CommonsBeansProvider(), AppProvider(settings))
    try:
        assert container.get(AIOKafkaConsumer) is consumer
        listener = container.get(SeekToEndListener)
        assert isinstance(listener, ConsumerRebalanceListener)
        asyncio.run(listener.on_partitions_assigned([("ads.engine.request", 0)]))
    finally:
        container.close()

    assert constructor_options == {
        "bootstrap_servers": settings.kafka_bootstrap_servers,
        "group_id": settings.consumer_group,
        "enable_auto_commit": False,
        "auto_offset_reset": "latest",
    }
    assert consumer.seeks == [(("ads.engine.request", 0), 4)]


def test_seek_assigned_to_end_skips_backlog() -> None:
    first = ("ads.engine.request", 0)
    second = ("ads.engine.request", 1)
    consumer = FakeConsumer({first: 12, second: 0})

    async def _body() -> None:
        await seek_assigned_to_end(consumer, {first, second})

    asyncio.run(_body())
    assert set(consumer.seeks) == {(first, 12), (second, 0)}
