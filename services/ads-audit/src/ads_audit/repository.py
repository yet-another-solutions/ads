from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import desc, select, tuple_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_audit.models import audit_decisions
from ads_policy.contract import AuditEvent, Capability, Effect, InterceptionPoint


@dataclass(frozen=True, slots=True)
class Cursor:
    recorded_at: datetime
    event_id: str

    def encode(self) -> str:
        query_string_safe_moment = (
            self.recorded_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        )
        return f"{query_string_safe_moment}|{self.event_id}"

    @staticmethod
    def decode(raw: str) -> Cursor:
        moment, _, event_id = raw.partition("|")
        if not moment or not event_id:
            raise ValueError("a cursor is <timestamp>|<event id>")
        return Cursor(datetime.fromisoformat(moment), event_id)


@dataclass(frozen=True, slots=True)
class Page:
    events: tuple[AuditEvent, ...]
    next_cursor: str | None


class AuditRepository(Protocol):
    async def append(self, event: AuditEvent) -> None: ...

    async def for_run(self, run_id: str) -> Sequence[AuditEvent]: ...

    async def for_subject(self, subject: str) -> Sequence[AuditEvent]: ...

    async def page(self, limit: int, cursor: Cursor | None = None) -> Page: ...


class UnitOfWork(Protocol):
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
    session: AsyncSession

    async def append(self, event: AuditEvent) -> None:
        statement = insert(audit_decisions).values(
            recorded_at=event.recorded_at,
            event_id=event.event_id,
            run_id=event.run_id,
            subject=event.subject,
            capability=event.capability.value if event.capability else None,
            resource=event.resource,
            effect=event.effect.value,
            rule_id=event.rule_id,
            weight=event.weight,
            policy_hash=event.policy_hash,
            content=event.content,
            point=event.point.value,
            decided_by=event.decided_by,
        )
        await self.session.execute(statement.on_conflict_do_nothing())

    async def for_run(self, run_id: str) -> Sequence[AuditEvent]:
        return await self._select(audit_decisions.c.run_id == run_id)

    async def for_subject(self, subject: str) -> Sequence[AuditEvent]:
        return await self._select(audit_decisions.c.subject == subject)

    async def page(self, limit: int, cursor: Cursor | None = None) -> Page:
        keyset = tuple_(audit_decisions.c.recorded_at, audit_decisions.c.event_id)
        statement = (
            select(audit_decisions)
            .order_by(desc(audit_decisions.c.recorded_at), desc(audit_decisions.c.event_id))
            .limit(limit + 1)
        )
        if cursor is not None:
            statement = statement.where(keyset < (cursor.recorded_at, cursor.event_id))
        page_and_one_more = (await self.session.execute(statement)).mappings().all()
        events = [_event(dict(row)) for row in page_and_one_more[:limit]]
        has_next_page = len(page_and_one_more) > limit
        following = Cursor(events[-1].recorded_at, events[-1].event_id) if has_next_page else None
        return Page(tuple(events), following.encode() if following else None)

    async def _select(self, condition: object) -> Sequence[AuditEvent]:
        statement = (
            select(audit_decisions)
            .where(condition)  # type: ignore[arg-type]
            .order_by(audit_decisions.c.recorded_at, audit_decisions.c.id)
        )
        rows = (await self.session.execute(statement)).mappings().all()
        return [_event(dict(row)) for row in rows]


class InMemoryAuditRepository:
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

    async def page(self, limit: int, cursor: Cursor | None = None) -> Page:
        ordered = sorted(self._events, key=lambda e: (e.recorded_at, e.event_id), reverse=True)
        if cursor is not None:
            key = (cursor.recorded_at, cursor.event_id)
            ordered = [e for e in ordered if (e.recorded_at, e.event_id) < key]
        events = ordered[:limit]
        following = (
            Cursor(events[-1].recorded_at, events[-1].event_id).encode()
            if len(ordered) > limit
            else None
        )
        return Page(tuple(events), following)

    def all(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)


def _event(row: Mapping[str, Any]) -> AuditEvent:
    return AuditEvent(
        run_id=str(row["run_id"]),
        subject=str(row["subject"]),
        capability=Capability(str(row["capability"])) if row["capability"] else None,
        resource=str(row["resource"]),
        effect=Effect(str(row["effect"])),
        rule_id=str(row["rule_id"]),
        weight=int(str(row["weight"])),
        policy_hash=str(row["policy_hash"]),
        content=None if row["content"] is None else str(row["content"]),
        point=InterceptionPoint(str(row["point"])),
        decided_by=str(row["decided_by"]),
        event_id=str(row["event_id"]),
        recorded_at=row["recorded_at"],
    )
