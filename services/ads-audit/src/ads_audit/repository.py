from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_audit.models import audit_decisions
from ads_policy.contract import AuditEvent, Capability, Effect


class AuditRepository(Protocol):
    """Append and read. There is deliberately no way to remove a row."""

    async def append(self, event: AuditEvent) -> None: ...

    async def for_run(self, run_id: str) -> Sequence[AuditEvent]: ...

    async def for_subject(self, subject: str) -> Sequence[AuditEvent]: ...


class UnitOfWork(Protocol):
    """One transaction on the boundary: the consumer opens it per delivery."""

    def __call__(self) -> AbstractAsyncContextManager[AuditRepository]: ...


def sql_unit_of_work(sessions: async_sessionmaker[AsyncSession]) -> UnitOfWork:
    @asynccontextmanager
    async def unit() -> AsyncIterator[AuditRepository]:
        async with sessions() as session, session.begin():
            yield SqlAuditRepository(session)

    return unit


def fixed_unit_of_work(repository: AuditRepository) -> UnitOfWork:
    @asynccontextmanager
    async def unit() -> AsyncIterator[AuditRepository]:
        yield repository

    return unit


@dataclass(frozen=True, slots=True, eq=False)
class SqlAuditRepository:
    """The journal in PostgreSQL. Redelivered events are ignored, never duplicated."""

    session: AsyncSession

    async def append(self, event: AuditEvent) -> None:
        statement = insert(audit_decisions).values(
            recorded_at=event.recorded_at,
            event_id=event.event_id,
            run_id=event.run_id,
            subject=event.subject,
            capability=event.capability.value,
            resource=event.resource,
            effect=event.effect.value,
            rule_id=event.rule_id,
            weight=event.weight,
            policy_hash=event.policy_hash,
            content=event.content,
        )
        await self.session.execute(statement.on_conflict_do_nothing())

    async def for_run(self, run_id: str) -> Sequence[AuditEvent]:
        return await self._select(audit_decisions.c.run_id == run_id)

    async def for_subject(self, subject: str) -> Sequence[AuditEvent]:
        return await self._select(audit_decisions.c.subject == subject)

    async def _select(self, condition: object) -> Sequence[AuditEvent]:
        statement = (
            select(audit_decisions)
            .where(condition)  # type: ignore[arg-type]
            .order_by(audit_decisions.c.recorded_at, audit_decisions.c.id)
        )
        rows = (await self.session.execute(statement)).mappings().all()
        return [_event(dict(row)) for row in rows]


class InMemoryAuditRepository:
    """Single-process stand-in for tests, with the same append-only surface."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._seen: set[str] = set()

    async def append(self, event: AuditEvent) -> None:
        if event.event_id in self._seen:
            return
        self._seen.add(event.event_id)
        self._events.append(event)

    async def for_run(self, run_id: str) -> Sequence[AuditEvent]:
        return [event for event in self._events if event.run_id == run_id]

    async def for_subject(self, subject: str) -> Sequence[AuditEvent]:
        return [event for event in self._events if event.subject == subject]

    def all(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)


def _event(row: Mapping[str, Any]) -> AuditEvent:
    return AuditEvent(
        run_id=str(row["run_id"]),
        subject=str(row["subject"]),
        capability=Capability(str(row["capability"])),
        resource=str(row["resource"]),
        effect=Effect(str(row["effect"])),
        rule_id=str(row["rule_id"]),
        weight=int(str(row["weight"])),
        policy_hash=str(row["policy_hash"]),
        content=None if row["content"] is None else str(row["content"]),
        event_id=str(row["event_id"]),
        recorded_at=row["recorded_at"],
    )
