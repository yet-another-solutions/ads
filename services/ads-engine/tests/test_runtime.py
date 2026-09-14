from __future__ import annotations

import asyncio

from ads_engine.runtime import seek_assigned_to_end


class FakeConsumer:
    def __init__(self, ends: dict[object, int]) -> None:
        self._ends = ends
        self.seeks: list[tuple[object, int]] = []

    async def end_offsets(self, partitions: list[object]) -> dict[object, int]:
        return {partition: self._ends[partition] for partition in partitions}

    def seek(self, partition: object, offset: int) -> None:
        self.seeks.append((partition, offset))


def test_seek_assigned_to_end_skips_backlog() -> None:
    first = ("ads.engine.request", 0)
    second = ("ads.engine.request", 1)
    consumer = FakeConsumer({first: 12, second: 0})

    async def _body() -> None:
        await seek_assigned_to_end(consumer, {first, second})

    asyncio.run(_body())
    assert set(consumer.seeks) == {(first, 12), (second, 0)}
