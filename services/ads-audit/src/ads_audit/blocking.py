from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

import anyio.to_thread
import structlog

from ads_audit.budget import DEFAULT_REPEAT_MULTIPLIER, deny_budget
from ads_audit.repository import AuditRepository, ConversationBlockRecord, UnitOfWork
from ads_policy.client import HttpPolicyClient, PolicyUnavailable
from ads_policy.contract import AuditEvent, Effect

logger = structlog.get_logger("ads.audit")

BLOCKED_BY = "ads-audit"
DEFAULT_CONVERSATION_BUDGET_LIMIT = 30


class PolicyBlocker(Protocol):
    async def block(self, conversation: str, budget: int) -> None: ...


@dataclass(frozen=True, slots=True, eq=False)
class HttpPolicyBlocker:
    client: HttpPolicyClient

    async def block(self, conversation: str, budget: int) -> None:
        await anyio.to_thread.run_sync(
            self.client.block_conversation, conversation, budget, BLOCKED_BY
        )


class UnconfiguredPolicyBlocker:
    async def block(self, conversation: str, budget: int) -> None:
        raise PolicyUnavailable("policy service is not configured")


@dataclass(frozen=True, slots=True, eq=False)
class ConversationGuard:
    policy: PolicyBlocker
    budget_limit: int = DEFAULT_CONVERSATION_BUDGET_LIMIT
    repeat_multiplier: int = DEFAULT_REPEAT_MULTIPLIER

    async def block_if_over_budget(
        self, repository: AuditRepository, event: AuditEvent
    ) -> ConversationBlockRecord | None:
        if event.effect is not Effect.DENY or not event.conversation:
            return None
        if await repository.conversation_block(event.conversation) is not None:
            return None
        budget = deny_budget(
            await repository.for_conversation(event.conversation), self.repeat_multiplier
        )
        if budget < self.budget_limit:
            return None
        block = await repository.block_conversation(event.conversation, budget)
        if block is not None:
            logger.warning(
                "conversation over its deny budget",
                conversation=block.conversation,
                budget=block.budget,
                limit=self.budget_limit,
            )
        return block

    async def tell_policy(self, block: ConversationBlockRecord) -> bool:
        try:
            await self.policy.block(block.conversation, block.budget)
        except (PolicyUnavailable, OSError) as exc:
            logger.warning(
                "conversation block not delivered to policy yet",
                conversation=block.conversation,
                error=str(exc),
            )
            return False
        return True

    async def tell_policy_about_every_block(self, unit_of_work: UnitOfWork) -> int:
        async with unit_of_work() as repository:
            blocks: Sequence[ConversationBlockRecord] = await repository.conversation_blocks()
        delivered = 0
        for block in blocks:
            if await self.tell_policy(block):
                delivered += 1
        return delivered
