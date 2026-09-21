from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

import msgspec
import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from ads.config import Settings
from ads.egress_controller import EgressRequestController
from ads.kafka import SeekToEndListener
from ads.tokens import TokenMinter
from ads_commons.egress import (
    EGRESS_CONFIG_TOPIC,
    EgressConfigUpdate,
    ProjectEgressSnapshot,
    canonical_settings,
)

log = structlog.get_logger("ads.egress.kafka")


class EgressKafka:
    """One app-owned producer; replicas compete for requests, IPC groups do not."""

    def __init__(self, settings: Settings, tokens: TokenMinter) -> None:
        self.settings, self.tokens = settings, tokens
        self.producer: Any = None
        self.consumer: Any = None
        self.controller: EgressRequestController | None = None
        self.task: asyncio.Task[None] | None = None
        self.started = False
        self.failed = False

    async def start(self) -> None:
        if self.started:
            return
        if self.controller is None:
            raise RuntimeError("egress request controller is required")
        self.producer = AIOKafkaProducer(**self.settings.kafka_options())
        self.consumer = AIOKafkaConsumer(
            **self.settings.kafka_options(),
            group_id=self.settings.egress_consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )
        try:
            async with asyncio.timeout(30):
                await self.producer.start()
                self.consumer.subscribe(
                    [EGRESS_CONFIG_TOPIC], listener=SeekToEndListener(self.consumer)
                )
                await self.consumer.start()
            self.started = True
            self.task = asyncio.create_task(self._consume())
        except BaseException:
            await self.stop()
            raise

    async def publish(self, project_id: UUID, snapshot: ProjectEgressSnapshot) -> None:
        if not self.started or self.failed:
            raise RuntimeError("configuration publisher unavailable")
        snapshot = ProjectEgressSnapshot(snapshot.revision, canonical_settings(snapshot.settings))
        async with asyncio.timeout(15):
            token = await asyncio.to_thread(self.tokens.exchange_service, "ads-sandbox-ipc")
            await self.producer.send_and_wait(
                EGRESS_CONFIG_TOPIC,
                key=str(project_id).encode(),
                value=msgspec.json.encode(EgressConfigUpdate(project_id, snapshot)),
                headers=[("authorization", token.encode())],
            )

    async def _consume(self) -> None:
        assert self.controller is not None
        try:
            async for record in self.consumer:
                await self.controller.on_record(record.value, record.headers)
                await self.consumer.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            self.failed = True
            log.error("egress_configuration_consumer_failed")
        finally:
            if self.started:
                self.failed = True
                log.error("egress_configuration_consumer_stopped")

    async def stop(self) -> None:
        self.started = False
        if self.task is not None:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
            self.task = None
        try:
            if self.consumer is not None:
                await self.consumer.stop()
        finally:
            if self.producer is not None:
                await self.producer.stop()
