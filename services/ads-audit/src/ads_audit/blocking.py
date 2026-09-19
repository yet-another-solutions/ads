from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

import anyio.to_thread
import structlog

from ads_audit.budget import DEFAULT_REPEAT_MULTIPLIER
from ads_audit.repository import AuditRepository, ConversationBlockRecord, UnitOfWork
from ads_policy.client import HttpPolicyClient, PolicyUnavailable
from ads_policy.contract import AuditEvent, Effect

logger = structlog.get_logger("ads.audit")

BLOCKED_BY = "ads-audit"
DEFAULT_CONVERSATION_BUDGET_LIMIT = 30


class PolicyBlocker(Protocol):
    async def block(self, conversation: str, budget: int) -> None: ...

    async def lift(self, conversation: str) -> None: ...


@dataclass(frozen=True, slots=True, eq=False)
class HttpPolicyBlocker:
    client: HttpPolicyClient

    async def block(self, conversation: str, budget: int) -> None:
        await anyio.to_thread.run_sync(
            self.client.block_conversation, conversation, budget, BLOCKED_BY
        )

    async def lift(self, conversation: str) -> None:
        await anyio.to_thread.run_sync(self.client.lift_conversation_block, conversation)


class UnconfiguredPolicyBlocker:
    async def block(self, conversation: str, budget: int) -> None:
        raise PolicyUnavailable("policy service is not configured")

    async def lift(self, conversation: str) -> None:
        raise PolicyUnavailable("policy service is not configured")


@dataclass(frozen=True, slots=True, eq=False)
class ConversationGuard:
    policy: PolicyBlocker
    budget_limit: int = DEFAULT_CONVERSATION_BUDGET_LIMIT
    repeat_multiplier: int = DEFAULT_REPEAT_MULTIPLIER
    _told_policy: dict[str, bool] = field(default_factory=dict, init=False)

    async def block_if_over_budget(
        self, repository: AuditRepository, event: AuditEvent
    ) -> ConversationBlockRecord | None:
        if event.effect is not Effect.DENY or not event.conversation:
            return None
        standing = await repository.conversation_block(event.conversation)
        if standing is not None and standing.in_force:
            return None
        budget = await repository.budget_for_conversation(
            event.conversation, self.repeat_multiplier
        )
        # A lifted block leaves its budget behind: a chat is blocked again by what it
        # spends after the lift, not by what an auditor has already forgiven.
        spent_since_the_lift = budget - (0 if standing is None else standing.lifted_budget)
        if spent_since_the_lift < self.budget_limit:
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
            self._told_policy.pop(block.conversation, None)
            logger.warning(
                "conversation block not delivered to policy yet",
                conversation=block.conversation,
                error=str(exc),
            )
            return False
        self._told_policy[block.conversation] = True
        return True

    async def tell_policy_to_lift(self, block: ConversationBlockRecord) -> bool:
        try:
            await self.policy.lift(block.conversation)
        except (PolicyUnavailable, OSError) as exc:
            self._told_policy.pop(block.conversation, None)
            logger.warning(
                "lifted block not delivered to policy yet",
                conversation=block.conversation,
                error=str(exc),
            )
            return False
        self._told_policy[block.conversation] = False
        return True

    async def tell_policy_what_it_is_missing(self, unit_of_work: UnitOfWork) -> int:
        """Send only what the policy service has not been told: a block, or a lift of one.

        What it has been told is remembered in this process, so a restart here re-sends
        everything once and then goes quiet.
        """
        async with unit_of_work() as repository:
            blocks: Sequence[ConversationBlockRecord] = await repository.conversation_blocks()
        delivered = 0
        for block in blocks:
            if self._told_policy.get(block.conversation) == block.in_force:
                continue
            told = (
                await self.tell_policy(block)
                if block.in_force
                else await self.tell_policy_to_lift(block)
            )
            delivered += 1 if told else 0
        return delivered
