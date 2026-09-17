from __future__ import annotations

import msgspec
import pytest

from ads_audit.blocking import ConversationGuard, UnconfiguredPolicyBlocker
from ads_audit.consumer import AuditConsumer
from ads_audit.repository import InMemoryAuditRepository, fixed_unit_of_work
from ads_policy.client import PolicyUnavailable
from ads_policy.contract import AuditEvent, Capability, Effect
from audit_helpers import denied

pytestmark = pytest.mark.anyio

CHAT = "3f2b6c1e-0000-4000-8000-000000000001"
OTHER_CHAT = "3f2b6c1e-0000-4000-8000-000000000002"
LIMIT = 10


class RecordingPolicy:
    def __init__(self) -> None:
        self.blocked: list[tuple[str, int]] = []

    async def block(self, conversation: str, budget: int) -> None:
        self.blocked.append((conversation, budget))


class UnreachablePolicy:
    async def block(self, conversation: str, budget: int) -> None:
        raise PolicyUnavailable("no route to the policy service")


class _Delivery:
    def __init__(self, event: AuditEvent) -> None:
        self.body = msgspec.json.encode(event)
        self.acked = False

    async def ack(self) -> None:
        self.acked = True


def _consumer(repository: InMemoryAuditRepository, guard: ConversationGuard) -> AuditConsumer:
    return AuditConsumer(
        None,  # type: ignore[arg-type]
        fixed_unit_of_work(repository),
        nack_pause_seconds=0.0,
        guard=guard,
    )


async def _deliver(consumer: AuditConsumer, *events: AuditEvent) -> list[_Delivery]:
    deliveries = [_Delivery(event) for event in events]
    for delivery in deliveries:
        await consumer.handle(delivery)  # type: ignore[arg-type]
    return deliveries


def _allowed_in(conversation: str) -> AuditEvent:
    return AuditEvent(
        run_id="run-1",
        subject="alice",
        capability=Capability.FS_READ,
        resource="/workspace/README.md",
        effect=Effect.ALLOW,
        rule_id="fs.read.workdir",
        weight=0,
        policy_hash="hash",
        conversation=conversation,
    )


async def test_a_conversation_under_its_budget_is_not_blocked(
    repository: InMemoryAuditRepository,
) -> None:
    policy = RecordingPolicy()
    consumer = _consumer(repository, ConversationGuard(policy, budget_limit=LIMIT))
    await _deliver(consumer, denied(weight=5, conversation=CHAT))
    assert policy.blocked == []
    assert await repository.conversation_block(CHAT) is None


async def test_a_conversation_over_its_budget_is_blocked_and_policy_is_told(
    repository: InMemoryAuditRepository,
) -> None:
    policy = RecordingPolicy()
    consumer = _consumer(repository, ConversationGuard(policy, budget_limit=LIMIT))
    deliveries = await _deliver(
        consumer,
        denied(resource="one", weight=5, conversation=CHAT),
        denied(resource="two", weight=5, conversation=CHAT),
    )
    assert all(delivery.acked for delivery in deliveries)
    assert policy.blocked == [(CHAT, 10)]
    block = await repository.conversation_block(CHAT)
    assert block is not None
    assert block.budget == 10


async def test_budget_counts_every_run_of_the_conversation(
    repository: InMemoryAuditRepository,
) -> None:
    policy = RecordingPolicy()
    consumer = _consumer(repository, ConversationGuard(policy, budget_limit=LIMIT))
    await _deliver(
        consumer,
        denied(run_id="run-1", resource="one", weight=5, conversation=CHAT),
        denied(run_id="run-2", resource="two", weight=5, conversation=CHAT),
    )
    assert policy.blocked == [(CHAT, 10)]


async def test_repeated_refusals_reach_the_budget_faster(
    repository: InMemoryAuditRepository,
) -> None:
    policy = RecordingPolicy()
    consumer = _consumer(repository, ConversationGuard(policy, budget_limit=LIMIT))
    await _deliver(
        consumer,
        denied(resource="same", weight=3, conversation=CHAT),
        denied(resource="same", weight=3, conversation=CHAT),
    )
    assert policy.blocked == [(CHAT, 12)]


async def test_a_blocked_conversation_is_blocked_once(
    repository: InMemoryAuditRepository,
) -> None:
    policy = RecordingPolicy()
    consumer = _consumer(repository, ConversationGuard(policy, budget_limit=LIMIT))
    await _deliver(
        consumer,
        denied(resource="one", weight=10, conversation=CHAT),
        denied(resource="two", weight=10, conversation=CHAT),
    )
    assert policy.blocked == [(CHAT, 10)]


async def test_refusals_of_other_conversations_do_not_add_up(
    repository: InMemoryAuditRepository,
) -> None:
    policy = RecordingPolicy()
    consumer = _consumer(repository, ConversationGuard(policy, budget_limit=LIMIT))
    await _deliver(
        consumer,
        denied(resource="one", weight=5, conversation=CHAT),
        denied(resource="two", weight=5, conversation=OTHER_CHAT),
    )
    assert policy.blocked == []


async def test_refusals_outside_any_conversation_never_block(
    repository: InMemoryAuditRepository,
) -> None:
    policy = RecordingPolicy()
    consumer = _consumer(repository, ConversationGuard(policy, budget_limit=LIMIT))
    await _deliver(consumer, denied(resource="one", weight=50))
    assert policy.blocked == []
    assert await repository.conversation_blocks() == []


async def test_permitted_calls_do_not_trigger_a_block(
    repository: InMemoryAuditRepository,
) -> None:
    policy = RecordingPolicy()
    await repository.append(denied(resource="one", weight=50, conversation=CHAT))
    consumer = _consumer(repository, ConversationGuard(policy, budget_limit=LIMIT))
    await _deliver(consumer, _allowed_in(CHAT))
    assert policy.blocked == []


async def test_an_unreachable_policy_keeps_the_block_and_the_event(
    repository: InMemoryAuditRepository,
) -> None:
    consumer = _consumer(repository, ConversationGuard(UnreachablePolicy(), budget_limit=LIMIT))
    deliveries = await _deliver(consumer, denied(weight=10, conversation=CHAT))
    assert deliveries[0].acked
    assert await repository.conversation_block(CHAT) is not None


async def test_every_stored_block_is_delivered_again(
    repository: InMemoryAuditRepository,
) -> None:
    await repository.block_conversation(CHAT, 31)
    await repository.block_conversation(OTHER_CHAT, 40)
    policy = RecordingPolicy()
    guard = ConversationGuard(policy, budget_limit=LIMIT)
    delivered = await guard.tell_policy_about_every_block(fixed_unit_of_work(repository))
    assert delivered == 2
    assert sorted(policy.blocked) == [(CHAT, 31), (OTHER_CHAT, 40)]


async def test_redelivery_counts_what_could_not_be_delivered() -> None:
    repository = InMemoryAuditRepository()
    await repository.block_conversation(CHAT, 31)
    guard = ConversationGuard(UnconfiguredPolicyBlocker(), budget_limit=LIMIT)
    assert await guard.tell_policy_about_every_block(fixed_unit_of_work(repository)) == 0
