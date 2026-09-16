from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import msgspec

from ads_audit.budget import DEFAULT_REPEAT_MULTIPLIER, deny_budget
from ads_audit.repository import AuditRepository, Cursor, Page
from ads_policy.contract import AuditEvent

#: A page anyone can ask for. The journal is partitioned and grows without end, so
#: there has to be a ceiling somewhere and it belongs here, not in the caller.
MAX_PAGE = 500


@dataclass(frozen=True, slots=True, eq=False)
class AuditService:
    """Writes what happened and answers what it adds up to."""

    repository: AuditRepository
    repeat_multiplier: int = DEFAULT_REPEAT_MULTIPLIER

    async def accept(self, body: bytes) -> AuditEvent:
        """Decode one delivery and journal it. An unreadable body is not an event."""
        event = msgspec.json.decode(body, type=AuditEvent)
        await self.repository.append(event)
        return event

    async def for_run(self, run_id: str) -> Sequence[AuditEvent]:
        """A run reads best in the order it happened, and it is bounded by its TTL."""
        return await self.repository.for_run(run_id)

    async def for_subject(self, subject: str) -> Sequence[AuditEvent]:
        return await self.repository.for_subject(subject)

    async def journal(self, limit: int, cursor: str | None = None) -> Page:
        """The whole journal, which is unbounded, so it only ever comes a page at a time."""
        bounded = max(1, min(limit, MAX_PAGE))
        return await self.repository.page(bounded, Cursor.decode(cursor) if cursor else None)

    async def budget_for_run(self, run_id: str) -> int:
        return deny_budget(await self.repository.for_run(run_id), self.repeat_multiplier)

    async def budget_for_subject(self, subject: str) -> int:
        """Accumulation across runs is a signal for a reviewer, not an automatic block."""
        return deny_budget(await self.repository.for_subject(subject), self.repeat_multiplier)
