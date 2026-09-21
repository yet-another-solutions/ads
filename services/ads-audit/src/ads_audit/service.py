from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

import msgspec

from ads_audit.budget import DEFAULT_REPEAT_MULTIPLIER
from ads_audit.repository import (
    WHOLE_JOURNAL,
    AuditRepository,
    ConversationBlockRecord,
    Cursor,
    JournalFilter,
    Page,
    SourceTraffic,
)
from ads_policy.contract import AuditEvent

MAX_PAGE = 500


@dataclass(frozen=True, slots=True, eq=False)
class AuditService:
    repository: AuditRepository
    repeat_multiplier: int = DEFAULT_REPEAT_MULTIPLIER

    async def accept(self, body: bytes) -> AuditEvent:
        event = msgspec.json.decode(body, type=AuditEvent)
        await self.repository.append(event)
        return event

    async def budget_for_conversation(self, conversation: str) -> int:
        return await self.repository.budget_for_conversation(conversation, self.repeat_multiplier)

    async def conversation_block(self, conversation: str) -> ConversationBlockRecord | None:
        return await self.repository.conversation_block(conversation)

    async def lift_conversation_block(
        self, conversation: str, by: str
    ) -> ConversationBlockRecord | None:
        """The budget at the lift is kept, so the chat is not blocked again by it."""
        budget = await self.repository.budget_for_conversation(conversation, self.repeat_multiplier)
        return await self.repository.lift_conversation_block(conversation, by, budget)

    async def journal(
        self, limit: int, cursor: str | None = None, where: JournalFilter = WHOLE_JOURNAL
    ) -> Page:
        return await self.repository.page(*self._paging(limit, cursor), where)

    async def event_at(self, position: str) -> AuditEvent | None:
        return await self.repository.event_at(Cursor.decode(position))

    async def traffic_by_source(self, since: datetime) -> Sequence[SourceTraffic]:
        return await self.repository.traffic_by_source(since)

    def _paging(self, limit: int, cursor: str | None) -> tuple[int, Cursor | None]:
        return max(1, min(limit, MAX_PAGE)), Cursor.decode(cursor) if cursor else None

    async def budget_for_run(self, run_id: str) -> int:
        return await self.repository.budget_for_run(run_id, self.repeat_multiplier)

    async def budget_for_subject(self, subject: str) -> int:
        return await self.repository.budget_for_subject(subject, self.repeat_multiplier)
