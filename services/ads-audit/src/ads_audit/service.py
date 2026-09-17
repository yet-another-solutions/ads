from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import msgspec

from ads_audit.budget import DEFAULT_REPEAT_MULTIPLIER, deny_budget
from ads_audit.repository import AuditRepository, ConversationBlockRecord, Cursor, Page
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

    async def for_run(self, run_id: str) -> Sequence[AuditEvent]:
        return await self.repository.for_run(run_id)

    async def for_subject(self, subject: str) -> Sequence[AuditEvent]:
        return await self.repository.for_subject(subject)

    async def for_conversation(self, conversation: str) -> Sequence[AuditEvent]:
        return await self.repository.for_conversation(conversation)

    async def budget_for_conversation(self, conversation: str) -> int:
        return deny_budget(
            await self.repository.for_conversation(conversation), self.repeat_multiplier
        )

    async def conversation_block(self, conversation: str) -> ConversationBlockRecord | None:
        return await self.repository.conversation_block(conversation)

    async def journal(self, limit: int, cursor: str | None = None) -> Page:
        page_size = max(1, min(limit, MAX_PAGE))
        return await self.repository.page(page_size, Cursor.decode(cursor) if cursor else None)

    async def budget_for_run(self, run_id: str) -> int:
        return deny_budget(await self.repository.for_run(run_id), self.repeat_multiplier)

    async def budget_for_subject(self, subject: str) -> int:
        return deny_budget(await self.repository.for_subject(subject), self.repeat_multiplier)
