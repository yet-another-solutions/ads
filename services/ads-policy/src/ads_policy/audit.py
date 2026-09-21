from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import aio_pika
import msgspec
from aio_pika.abc import AbstractRobustConnection

from ads_policy.contract import AuditEvent, DecisionRequest, PolicyDecision

EXCHANGE = "ads.audit"
ROUTING_KEY = "decision"
QUEUE = "ads.audit.decisions"
RESERVED_FOR_REFUSALS = 100


def record(
    request: DecisionRequest,
    decision: PolicyDecision,
    *,
    content: str | None = None,
    include_content: bool = False,
    conversation: str = "",
) -> AuditEvent:
    return AuditEvent(
        run_id=request.run_id,
        subject=request.subject,
        capability=request.capability,
        resource=request.resource,
        effect=decision.effect,
        rule_id=decision.rule_id,
        weight=decision.weight,
        policy_hash=decision.policy_hash,
        content=content if include_content else None,
        point=decision.point,
        conversation=conversation,
        source=request.source,
        tool=request.tool,
    )


class AuditBacklogFull(RuntimeError):
    pass


class AuditSink(Protocol):
    async def send(self, event: AuditEvent) -> None: ...


@dataclass(frozen=True, slots=True, eq=False)
class RabbitAuditSink:
    connection: AbstractRobustConnection

    async def send(self, event: AuditEvent) -> None:
        channel = await self.connection.channel()
        exchange = await channel.declare_exchange(
            EXCHANGE, aio_pika.ExchangeType.DIRECT, durable=True
        )
        await exchange.publish(
            aio_pika.Message(
                body=msgspec.json.encode(event),
                content_type="application/json",
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            ),
            routing_key=ROUTING_KEY,
        )


class BufferedAuditSink:
    def __init__(
        self,
        sink: AuditSink,
        capacity: int = 10000,
        decided_by: str = "",
    ) -> None:
        self._sink = sink
        self._capacity = capacity
        self._room_for_decisions = self._capacity - self._capacity // RESERVED_FOR_REFUSALS
        self._decided_by = decided_by
        self._pending: list[AuditEvent] = []
        self._lost = 0

    @property
    def pending(self) -> tuple[AuditEvent, ...]:
        return tuple(self._pending)

    @property
    def lost(self) -> int:
        return self._lost

    @property
    def saturated(self) -> bool:
        return len(self._pending) >= self._room_for_decisions

    def enqueue(self, event: AuditEvent) -> None:
        if self.saturated:
            self._lost += 1
            raise AuditBacklogFull(f"{self._capacity} events are waiting to be journalled")
        self._remember(event)

    def enqueue_refusal(self, event: AuditEvent) -> None:
        if len(self._pending) >= self._capacity:
            self._lost += 1
            return
        self._remember(event)

    def _remember(self, event: AuditEvent) -> None:
        if self._decided_by:
            event = msgspec.structs.replace(event, decided_by=self._decided_by)
        self._pending.append(event)

    async def drain(self) -> int:
        sent = 0
        while self._pending:
            try:
                await self._sink.send(self._pending[0])
            except Exception:
                break
            self._pending.pop(0)
            sent += 1
        return sent


class CollectingAuditSink:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    async def send(self, event: AuditEvent) -> None:
        self._events.append(event)

    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)
