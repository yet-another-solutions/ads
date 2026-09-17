from __future__ import annotations

from dataclasses import dataclass

import aio_pika
import anyio
import msgspec
import structlog
from aio_pika.abc import AbstractIncomingMessage, AbstractRobustConnection

from ads_audit.repository import UnitOfWork
from ads_policy.audit import EXCHANGE, QUEUE, ROUTING_KEY
from ads_policy.contract import AuditEvent

logger = structlog.get_logger("ads.audit")


@dataclass(frozen=True, slots=True, eq=False)
class AuditConsumer:
    connection: AbstractRobustConnection
    unit_of_work: UnitOfWork
    prefetch: int = 100
    nack_pause_seconds: float = 1.0

    async def start(self) -> None:
        channel = await self.connection.channel()
        await channel.set_qos(prefetch_count=self.prefetch)
        exchange = await channel.declare_exchange(
            EXCHANGE, aio_pika.ExchangeType.DIRECT, durable=True
        )
        queue = await channel.declare_queue(QUEUE, durable=True)
        await queue.bind(exchange, ROUTING_KEY)
        await queue.consume(self.handle)

    async def handle(self, message: AbstractIncomingMessage) -> None:
        try:
            event = msgspec.json.decode(message.body, type=AuditEvent)
        except msgspec.DecodeError:
            logger.error("audit event rejected", body=message.body[:512])
            await message.reject(requeue=False)
            return
        try:
            async with self.unit_of_work() as repository:
                await repository.append(event)
        except Exception:
            logger.exception("audit event not journalled", event_id=event.event_id)
            await anyio.sleep(self.nack_pause_seconds)
            await message.nack(requeue=True)
            return
        await message.ack()
