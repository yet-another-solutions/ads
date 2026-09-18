from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server import Server

from ads_sandbox_mcp.kafka import KafkaRuntime
from ads_sandbox_mcp.scheduler import ClusterScheduler


class McpRuntime:
    """One lifecycle for Kafka, the scheduler, and the SDK session manager."""

    def __init__(self, sdk: Server[Any], kafka: KafkaRuntime, scheduler: ClusterScheduler) -> None:
        self.sdk = sdk
        self._kafka = kafka
        self._scheduler = scheduler

    def ready(self) -> bool:
        return self._kafka.ready()

    @asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        await self._kafka.start()
        try:
            await self._scheduler.start()
            async with self.sdk.session_manager.run():
                yield
        finally:
            try:
                await self._scheduler.stop()
            finally:
                await self._kafka.stop()
