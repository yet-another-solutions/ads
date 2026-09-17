from __future__ import annotations

import msgspec
import pytest

from ads_audit.consumer import AuditConsumer
from ads_audit.repository import AuditRepository, InMemoryAuditRepository, fixed_unit_of_work
from ads_policy.contract import AuditEvent, Capability, Effect

pytestmark = pytest.mark.anyio


class _Delivery:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.acked = False
        self.nacked = False
        self.rejected = False
        self.requeued: bool | None = None

    async def ack(self) -> None:
        self.acked = True

    async def nack(self, requeue: bool = True) -> None:
        self.nacked = True
        self.requeued = requeue

    async def reject(self, requeue: bool = True) -> None:
        self.rejected = True
        self.requeued = requeue


class _BrokenRepository:
    async def append(self, event: AuditEvent) -> None:
        raise ConnectionError("journal unreachable")

    async def for_run(self, run_id: str) -> list[AuditEvent]:
        return []

    async def for_subject(self, subject: str) -> list[AuditEvent]:
        return []


def _event(resource: str = "ads-client-secret") -> AuditEvent:
    return AuditEvent(
        run_id="run-1",
        subject="alice",
        capability=Capability.SECRET_READ,
        resource=resource,
        effect=Effect.DENY,
        rule_id="secret.read",
        weight=5,
        policy_hash="hash",
    )


def _consumer(repository: AuditRepository) -> AuditConsumer:
    return AuditConsumer(
        None,  # type: ignore[arg-type]
        fixed_unit_of_work(repository),
        nack_pause_seconds=0.0,
    )


async def test_an_event_is_journalled_and_acknowledged(
    repository: InMemoryAuditRepository,
) -> None:
    event = _event()
    delivery = _Delivery(msgspec.json.encode(event))
    await _consumer(repository).handle(delivery)  # type: ignore[arg-type]
    assert repository.all() == (event,)
    assert delivery.acked


async def test_nothing_is_acknowledged_before_it_lands() -> None:
    delivery = _Delivery(msgspec.json.encode(_event()))
    await _consumer(_BrokenRepository()).handle(delivery)  # type: ignore[arg-type]
    assert not delivery.acked
    assert delivery.nacked
    assert delivery.requeued is True


@pytest.mark.parametrize("body", [b'{"run_id": 42}', b"not json at all", b"", b"\xff\xfe"])
async def test_a_malformed_body_is_rejected_so_it_does_not_block_the_queue(
    body: bytes, repository: InMemoryAuditRepository
) -> None:
    delivery = _Delivery(body)
    await _consumer(repository).handle(delivery)  # type: ignore[arg-type]
    assert delivery.rejected
    assert delivery.requeued is False
    assert not delivery.acked
    assert not delivery.nacked
    assert repository.all() == ()


async def test_a_redelivery_does_not_duplicate(repository: InMemoryAuditRepository) -> None:
    body = msgspec.json.encode(_event())
    consumer = _consumer(repository)
    first = _Delivery(body)
    second = _Delivery(body)
    await consumer.handle(first)  # type: ignore[arg-type]
    await consumer.handle(second)  # type: ignore[arg-type]
    assert len(repository.all()) == 1
    assert first.acked
    assert second.acked
