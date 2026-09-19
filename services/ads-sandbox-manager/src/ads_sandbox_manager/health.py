from __future__ import annotations

import asyncio
import ssl
from typing import Protocol

from aiokafka.client import AIOKafkaClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from ads_sandbox_manager.config import Settings


class Dependencies(Protocol):
    async def check(self) -> bool: ...


class DependencyHealth:
    """Connectivity only, with an application-owned Kafka metadata client."""

    def __init__(self, settings: Settings, engine: AsyncEngine) -> None:
        self.settings = settings
        self.engine = engine
        self._kafka: AIOKafkaClient | None = None

    async def check(self) -> bool:
        s = self.settings
        async with asyncio.timeout(s.control_seconds):
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        try:
            async with asyncio.timeout(s.control_seconds):
                if self._kafka is None:
                    self._kafka = self._new_kafka()
                    await self._kafka.bootstrap()
                healthy = await self._kafka.force_metadata_update()
        except BaseException:
            await self.close()
            raise
        if not healthy:
            await self.close()
        return bool(healthy)

    async def close(self) -> None:
        kafka, self._kafka = self._kafka, None
        if kafka is not None:
            await kafka.close()

    def _new_kafka(self) -> AIOKafkaClient:
        s = self.settings
        context = None
        if s.kafka_security_protocol in ("SSL", "SASL_SSL"):
            context = ssl.create_default_context(
                cafile=str(s.kafka_ca_bundle) if s.kafka_ca_bundle else None
            )
        return AIOKafkaClient(
            bootstrap_servers=s.kafka_bootstrap_servers,
            client_id="ads-sandbox-manager-health",
            request_timeout_ms=max(1, int(s.control_seconds * 1000)),
            security_protocol=s.kafka_security_protocol,
            sasl_mechanism=s.kafka_sasl_mechanism,
            sasl_plain_username=s.kafka_sasl_username,
            sasl_plain_password=s.kafka_sasl_password,
            ssl_context=context,
        )
