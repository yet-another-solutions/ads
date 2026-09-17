from __future__ import annotations

from dataclasses import dataclass

import aio_pika
import anyio
import msgspec
import structlog
from aio_pika.abc import AbstractIncomingMessage, AbstractRobustConnection

from ads_audit.blocking import ConversationGuard
from ads_audit.repository import ConversationBlockRecord, UnitOfWork
from ads_policy.audit import EXCHANGE, QUEUE, ROUTING_KEY
from ads_policy.contract import AuditEvent

logger = structlog.get_logger("ads.audit")


@dataclass(frozen=True, slots=True, eq=False)
class AuditConsumer:
    connection: AbstractRobustConnection
    unit_of_work: UnitOfWork
    prefetch: int = 100
    nack_pause_seconds: float = 1.0
    guard: ConversationGuard | None = None

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
        new_block: ConversationBlockRecord | None = None
        try:
            async with self.unit_of_work() as repository:
                await repository.append(event)
                if self.guard is not None:
                    new_block = await self.guard.block_if_over_budget(repository, event)
        except Exception:
            logger.exception("audit event not journalled", event_id=event.event_id)
            await anyio.sleep(self.nack_pause_seconds)
            await message.nack(requeue=True)
            return
        if new_block is not None and self.guard is not None:
            await self.guard.tell_policy(new_block)
        await message.ack()
