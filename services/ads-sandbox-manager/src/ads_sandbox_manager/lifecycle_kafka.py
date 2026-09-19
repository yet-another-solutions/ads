from __future__ import annotations

import asyncio
import logging
from collections.abc import Collection
from typing import Any

from aiokafka.abc import ConsumerRebalanceListener

from ads_sandbox_manager.controller import KafkaController

log = logging.getLogger(__name__)


class DurableAdmission(ConsumerRebalanceListener):  # type: ignore[misc]
    """Serial per partition; commit n+1 only after durable admission of n.

    No seek-to-end, auto-commit, fetched-position commit, or within-partition fanout.
    Rebalances fence offset retries, and replay after DB success is idempotent.
    """

    def __init__(self, consumer: Any, controller: KafkaController) -> None:
        self.consumer, self.controller = consumer, controller
        self.epochs: dict[Any, int] = {}
        self.generation = 0
        self.tasks: dict[Any, asyncio.Task[None]] = {}
        self.running: set[asyncio.Task[None]] = set()

    async def on_partitions_revoked(self, revoked: Collection[Any]) -> None:
        for partition in revoked:
            self.epochs.pop(partition, None)
            task = self.tasks.pop(partition, None)
            if task is not None:
                task.cancel()

    async def on_partitions_assigned(self, assigned: Collection[Any]) -> None:
        self.generation += 1
        self.epochs.update({partition: self.generation for partition in assigned})

    async def partition(self, partition: Any, records: list[Any], epoch: int) -> None:
        for record in records:
            admitted = False
            while self.epochs.get(partition) == epoch:
                try:
                    if not admitted:
                        await self.controller.admit_lifecycle(
                            record.topic,
                            record.value,
                            record.key,
                            record.headers,
                        )
                        admitted = True
                    if self.epochs.get(partition) != epoch:
                        return
                    await self.consumer.commit({partition: record.offset + 1})
                    break
                except Exception:
                    log.warning("lifecycle admission or explicit offset commit unavailable")
                    await asyncio.sleep(0.1)
            else:
                return

    async def _batch(self, partition: Any, records: list[Any], epoch: int) -> None:
        try:
            await self.partition(partition, records, epoch)
        finally:
            if self.epochs.get(partition) == epoch:
                self.tasks.pop(partition, None)
                self.consumer.resume(partition)

    async def run(self) -> None:
        try:
            while True:
                batches = await self.consumer.getmany(timeout_ms=1000, max_records=100)
                for partition, records in batches.items():
                    if partition not in self.epochs or not records:
                        continue
                    # Bound buffered work and stop fetching this partition, not other ones.
                    self.consumer.pause(partition)
                    task = asyncio.create_task(
                        self._batch(partition, records, self.epochs[partition])
                    )
                    self.tasks[partition] = task
                    self.running.add(task)
                    task.add_done_callback(self.running.discard)
        finally:
            tasks = list(self.running)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.tasks.clear()
