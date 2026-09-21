from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ads_audit.blocking import ConversationGuard
from ads_audit.chats import Chat, Chats
from ads_audit.policy_sources import PolicySources
from ads_audit.repository import ConversationBlockRecord, JournalFilter, Page
from ads_audit.service import AuditService
from ads_commons.security import check_role
from ads_policy.client import PolicyUnavailable
from ads_policy.contract import AuditEvent, Switch

JOURNAL_PAGE = 50
TRAFFIC_WINDOW = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class SourceRow:
    source: str
    checks: Switch | None
    allowed: int = 0
    denied: int = 0
    unchecked: int = 0


@dataclass(frozen=True, slots=True)
class SourcesView:
    rows: tuple[SourceRow, ...]
    policy_answered: bool
    since: datetime


@dataclass(frozen=True, slots=True, eq=False)
class AuditorDesk:
    journal: AuditService
    guard: ConversationGuard
    policy: PolicySources
    chats: Chats
    auditor_role: str

    async def page(self, where: JournalFilter, cursor: str | None = None) -> Page:
        check_role(self.auditor_role)
        return await self.journal.journal(JOURNAL_PAGE, cursor, where)

    async def event(self, position: str) -> AuditEvent | None:
        check_role(self.auditor_role)
        return await self.journal.event_at(position)

    async def chat(self, conversation: str) -> Chat | None:
        check_role(self.auditor_role)
        return await self.chats.transcript(conversation)

    async def blocks(self) -> Sequence[ConversationBlockRecord]:
        check_role(self.auditor_role)
        blocks = await self.journal.conversation_blocks()
        return sorted(blocks, key=lambda block: block.blocked_at, reverse=True)

    async def lift(self, conversation: str) -> ConversationBlockRecord | None:
        auditor = check_role(self.auditor_role).subject
        lifted = await self.journal.lift_conversation_block(conversation, auditor)
        if lifted is not None:
            await self.guard.tell_policy_to_lift(lifted)
        return lifted

    async def sources(self) -> SourcesView:
        check_role(self.auditor_role)
        since = datetime.now(UTC) - TRAFFIC_WINDOW
        traffic = {row.source: row for row in await self.journal.traffic_by_source(since)}
        try:
            checks = {row.source: row.checks for row in await self.policy.sources()}
            policy_answered = True
        except PolicyUnavailable:
            checks, policy_answered = {}, False
        rows = tuple(
            SourceRow(
                source=source,
                checks=checks.get(source),
                allowed=traffic[source].allowed if source in traffic else 0,
                denied=traffic[source].denied if source in traffic else 0,
                unchecked=traffic[source].unchecked if source in traffic else 0,
            )
            for source in sorted(checks.keys() | traffic.keys())
        )
        return SourcesView(rows, policy_answered, since)
