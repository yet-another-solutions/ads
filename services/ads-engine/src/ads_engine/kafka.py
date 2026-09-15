from __future__ import annotations

from collections.abc import Collection
from typing import Any, Protocol

from aiokafka.abc import ConsumerRebalanceListener


class OffsetSeeker(Protocol):
    async def end_offsets(self, partitions: list[Any]) -> dict[Any, int]: ...

    def seek(self, partition: Any, offset: int) -> None: ...


class SeekToEndListener(ConsumerRebalanceListener):
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
