from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import Select, case, desc, func, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_audit.budget import deny_budget
from ads_audit.models import audit_decisions, conversation_blocks
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
        recorded_at = datetime.fromisoformat(moment)
        if recorded_at.tzinfo is None:
            raise ValueError("a cursor's moment needs a time zone")
        return Cursor(recorded_at.astimezone(UTC), event_id)


@dataclass(frozen=True, slots=True)
class Page:
    events: tuple[AuditEvent, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class ConversationBlockRecord:
    conversation: str
    blocked_at: datetime
    budget: int
    lifted_at: datetime | None = None
    lifted_by: str = ""
    lifted_budget: int = 0

    @property
    def in_force(self) -> bool:
        return self.lifted_at is None


class AuditRepository(Protocol):
    async def append(self, event: AuditEvent) -> None: ...

    async def for_run(self, run_id: str, limit: int, cursor: Cursor | None = None) -> Page: ...

    async def for_subject(self, subject: str, limit: int, cursor: Cursor | None = None) -> Page: ...

    async def for_conversation(
        self, conversation: str, limit: int, cursor: Cursor | None = None
    ) -> Page: ...

    async def budget_for_run(self, run_id: str, repeat_multiplier: int) -> int: ...

    async def budget_for_subject(self, subject: str, repeat_multiplier: int) -> int: ...

    async def budget_for_conversation(self, conversation: str, repeat_multiplier: int) -> int: ...

    async def page(self, limit: int, cursor: Cursor | None = None) -> Page: ...

    async def block_conversation(
        self, conversation: str, budget: int
    ) -> ConversationBlockRecord | None: ...

    async def lift_conversation_block(
        self, conversation: str, by: str, budget: int
    ) -> ConversationBlockRecord | None: ...

    async def conversation_block(self, conversation: str) -> ConversationBlockRecord | None: ...

    async def conversation_blocks(self) -> Sequence[ConversationBlockRecord]: ...


class UnitOfWork(Protocol):
    def __call__(self) -> AbstractAsyncContextManager[AuditRepository]: ...


def deny_budget_statement(condition: object, repeat_multiplier: int) -> Select[tuple[int]]:
    denied_before = (
        func.row_number()
        .over(
            partition_by=(audit_decisions.c.capability, audit_decisions.c.resource),
            order_by=(audit_decisions.c.recorded_at, audit_decisions.c.id),
        )
        .label("denied_before")
    )
    denials = (
        select(audit_decisions.c.weight, denied_before)
        .where(condition, audit_decisions.c.effect == Effect.DENY.value)  # type: ignore[arg-type]
        .subquery()
    )
    cost = case(
        (denials.c.denied_before > 1, denials.c.weight * repeat_multiplier),
        else_=denials.c.weight,
    )
    return select(func.coalesce(func.sum(cost), 0)).select_from(denials)


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
            conversation=event.conversation,
        )
        await self.session.execute(statement.on_conflict_do_nothing())

    async def for_run(self, run_id: str, limit: int, cursor: Cursor | None = None) -> Page:
        return await self._page(audit_decisions.c.run_id == run_id, limit, cursor)

    async def for_subject(self, subject: str, limit: int, cursor: Cursor | None = None) -> Page:
        return await self._page(audit_decisions.c.subject == subject, limit, cursor)

    async def for_conversation(
        self, conversation: str, limit: int, cursor: Cursor | None = None
    ) -> Page:
        return await self._page(audit_decisions.c.conversation == conversation, limit, cursor)

    async def budget_for_run(self, run_id: str, repeat_multiplier: int) -> int:
        return await self._budget(audit_decisions.c.run_id == run_id, repeat_multiplier)

    async def budget_for_subject(self, subject: str, repeat_multiplier: int) -> int:
        return await self._budget(audit_decisions.c.subject == subject, repeat_multiplier)

    async def budget_for_conversation(self, conversation: str, repeat_multiplier: int) -> int:
        return await self._budget(audit_decisions.c.conversation == conversation, repeat_multiplier)

    async def _budget(self, condition: object, repeat_multiplier: int) -> int:
        total = await self.session.execute(deny_budget_statement(condition, repeat_multiplier))
        return int(total.scalar_one())

    async def block_conversation(
        self, conversation: str, budget: int
    ) -> ConversationBlockRecord | None:
        """A chat blocked again after a lift takes over its row; one row is its state."""
        blocking = insert(conversation_blocks).values(conversation=conversation, budget=budget)
        statement = blocking.on_conflict_do_update(
            index_elements=[conversation_blocks.c.conversation],
            set_={
                "blocked_at": func.now(),
                "budget": budget,
                "lifted_at": None,
                "lifted_by": None,
                "lifted_budget": None,
            },
            where=conversation_blocks.c.lifted_at.isnot(None),
        ).returning(conversation_blocks)
        row = (await self.session.execute(statement)).mappings().first()
        return None if row is None else _block(dict(row))

    async def lift_conversation_block(
        self, conversation: str, by: str, budget: int
    ) -> ConversationBlockRecord | None:
        statement = (
            update(conversation_blocks)
            .where(
                conversation_blocks.c.conversation == conversation,
                conversation_blocks.c.lifted_at.is_(None),
            )
            .values(lifted_at=func.now(), lifted_by=by, lifted_budget=budget)
            .returning(conversation_blocks)
        )
        row = (await self.session.execute(statement)).mappings().first()
        return None if row is None else _block(dict(row))

    async def conversation_block(self, conversation: str) -> ConversationBlockRecord | None:
        statement = select(conversation_blocks).where(
            conversation_blocks.c.conversation == conversation
        )
        row = (await self.session.execute(statement)).mappings().first()
        return None if row is None else _block(dict(row))

    async def conversation_blocks(self) -> Sequence[ConversationBlockRecord]:
        statement = select(conversation_blocks).order_by(conversation_blocks.c.blocked_at)
        rows = (await self.session.execute(statement)).mappings().all()
        return [_block(dict(row)) for row in rows]

    async def page(self, limit: int, cursor: Cursor | None = None) -> Page:
        return await self._page(None, limit, cursor)

    async def _page(self, condition: object | None, limit: int, cursor: Cursor | None) -> Page:
        keyset = tuple_(audit_decisions.c.recorded_at, audit_decisions.c.event_id)
        statement = (
            select(audit_decisions)
            .order_by(desc(audit_decisions.c.recorded_at), desc(audit_decisions.c.event_id))
            .limit(limit + 1)
        )
        if condition is not None:
            statement = statement.where(condition)  # type: ignore[arg-type]
        if cursor is not None:
            statement = statement.where(keyset < (cursor.recorded_at, cursor.event_id))
        page_and_one_more = (await self.session.execute(statement)).mappings().all()
        events = [_event(dict(row)) for row in page_and_one_more[:limit]]
        has_next_page = len(page_and_one_more) > limit
        following = Cursor(events[-1].recorded_at, events[-1].event_id) if has_next_page else None
        return Page(tuple(events), following.encode() if following else None)


class InMemoryAuditRepository:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._seen: set[tuple[datetime, str]] = set()
        self._blocks: dict[str, ConversationBlockRecord] = {}

    async def for_conversation(
        self, conversation: str, limit: int, cursor: Cursor | None = None
    ) -> Page:
        return self._page(self._of_conversation(conversation), limit, cursor)

    async def block_conversation(
        self, conversation: str, budget: int
    ) -> ConversationBlockRecord | None:
        standing = self._blocks.get(conversation)
        if standing is not None and standing.in_force:
            return None
        block = ConversationBlockRecord(conversation, datetime.now(UTC), budget)
        self._blocks[conversation] = block
        return block

    async def lift_conversation_block(
        self, conversation: str, by: str, budget: int
    ) -> ConversationBlockRecord | None:
        standing = self._blocks.get(conversation)
        if standing is None or not standing.in_force:
            return None
        lifted = replace(standing, lifted_at=datetime.now(UTC), lifted_by=by, lifted_budget=budget)
        self._blocks[conversation] = lifted
        return lifted

    async def conversation_block(self, conversation: str) -> ConversationBlockRecord | None:
        return self._blocks.get(conversation)

    async def conversation_blocks(self) -> Sequence[ConversationBlockRecord]:
        return list(self._blocks.values())

    async def append(self, event: AuditEvent) -> None:
        same_row = (event.recorded_at, event.event_id)
        if same_row in self._seen:
            return
        self._seen.add(same_row)
        self._events.append(event)

    async def for_run(self, run_id: str, limit: int, cursor: Cursor | None = None) -> Page:
        return self._page(self._of_run(run_id), limit, cursor)

    async def for_subject(self, subject: str, limit: int, cursor: Cursor | None = None) -> Page:
        return self._page(self._of_subject(subject), limit, cursor)

    async def budget_for_run(self, run_id: str, repeat_multiplier: int) -> int:
        return deny_budget(self._of_run(run_id), repeat_multiplier)

    async def budget_for_subject(self, subject: str, repeat_multiplier: int) -> int:
        return deny_budget(self._of_subject(subject), repeat_multiplier)

    async def budget_for_conversation(self, conversation: str, repeat_multiplier: int) -> int:
        return deny_budget(self._of_conversation(conversation), repeat_multiplier)

    async def page(self, limit: int, cursor: Cursor | None = None) -> Page:
        return self._page(self._events, limit, cursor)

    def _of_run(self, run_id: str) -> list[AuditEvent]:
        return [event for event in self._events if event.run_id == run_id]

    def _of_subject(self, subject: str) -> list[AuditEvent]:
        return [event for event in self._events if event.subject == subject]

    def _of_conversation(self, conversation: str) -> list[AuditEvent]:
        return [event for event in self._events if event.conversation == conversation]

    def _page(self, among: Sequence[AuditEvent], limit: int, cursor: Cursor | None) -> Page:
        ordered = sorted(among, key=lambda e: (e.recorded_at, e.event_id), reverse=True)
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
        conversation=str(row["conversation"]),
        event_id=str(row["event_id"]),
        recorded_at=row["recorded_at"],
    )


def _block(row: Mapping[str, Any]) -> ConversationBlockRecord:
    lifted_budget = row.get("lifted_budget")
    return ConversationBlockRecord(
        conversation=str(row["conversation"]),
        blocked_at=row["blocked_at"],
        budget=int(str(row["budget"])),
        lifted_at=row.get("lifted_at"),
        lifted_by=str(row.get("lifted_by") or ""),
        lifted_budget=0 if lifted_budget is None else int(str(lifted_budget)),
    )
