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
    """Connectivity only. No migrations, Kafka subscriptions, topics, or STE in slice 7."""

    def __init__(self, settings: Settings, engine: AsyncEngine) -> None:
        self.settings = settings
        self.engine = engine

    async def check(self) -> bool:
        s = self.settings
        async with asyncio.timeout(s.control_seconds):
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        context = None
        if s.kafka_security_protocol in ("SSL", "SASL_SSL"):
            context = ssl.create_default_context(
                cafile=str(s.kafka_ca_bundle) if s.kafka_ca_bundle else None
            )
        kafka = AIOKafkaClient(
            bootstrap_servers=s.kafka_bootstrap_servers,
            client_id="ads-sandbox-manager-health",
            request_timeout_ms=max(1, int(s.control_seconds * 1000)),
            security_protocol=s.kafka_security_protocol,
            sasl_mechanism=s.kafka_sasl_mechanism,
            sasl_plain_username=s.kafka_sasl_username,
            sasl_plain_password=s.kafka_sasl_password,
            ssl_context=context,
        )
        try:
            async with asyncio.timeout(s.control_seconds):
                await kafka.bootstrap()
            return True
        finally:
            await kafka.close()
