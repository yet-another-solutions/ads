from __future__ import annotations

from dataclasses import dataclass

import msgspec

from ads_audit.budget import DEFAULT_REPEAT_MULTIPLIER, deny_budget
from ads_audit.repository import AuditRepository
from ads_policy.contract import AuditEvent


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

    async def budget_for_run(self, run_id: str) -> int:
        return deny_budget(await self.repository.for_run(run_id), self.repeat_multiplier)

    async def budget_for_subject(self, subject: str) -> int:
        """Accumulation across runs is a signal for a reviewer, not an automatic block."""
        return deny_budget(await self.repository.for_subject(subject), self.repeat_multiplier)
