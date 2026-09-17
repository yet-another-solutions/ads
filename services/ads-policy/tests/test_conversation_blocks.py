from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import msgspec
import pytest
from litestar.testing import TestClient
from redis.asyncio import Redis

from ads_policy.app import create_app
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.blocks import (
    BLOCK_PREFIX,
    ConversationBlock,
    ConversationBlocks,
    InMemoryConversationBlocks,
    RedisConversationBlocks,
)
from ads_policy.config import GovernanceSettings, Settings
from ads_policy.contract import Capability, Effect, IsolationLevel, Mode, RunRequest, RunState
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.run import RunStore
from ads_policy.service import PolicyService
from policy_helpers import decision_request, run_request

TOKEN = "policy-api-token-32-bytes-long"
CHAT = "3f2b6c1e-0000-4000-8000-000000000001"
OTHER_CHAT = "3f2b6c1e-0000-4000-8000-000000000002"
WORKDIR_FILE = "/workspace/README.md"
BLOCKED_AT = datetime(2026, 9, 1, tzinfo=UTC)


def _vm_run_in(conversation: str) -> RunRequest:
    return msgspec.structs.replace(run_request(IsolationLevel.VM), conversation=conversation)


def _block_of(conversation: str, budget: int = 31) -> ConversationBlock:
    return ConversationBlock(conversation, BLOCKED_AT, budget, "ads-audit")


@pytest.fixture(params=["memory", "redis"])
def blocks(request: pytest.FixtureRequest, redis: Redis) -> ConversationBlocks:
    if request.param == "memory":
        return InMemoryConversationBlocks()
    return RedisConversationBlocks(redis)


@pytest.fixture
def blocking_service(
    pdp: PolicyDecisionPoint,
    runs: RunStore,
    audit: BufferedAuditSink,
    blocks: ConversationBlocks,
) -> PolicyService:
    return PolicyService(pdp, runs, audit, blocks=blocks)


@pytest.mark.anyio
async def test_a_run_keeps_the_conversation_it_was_opened_for(
    blocking_service: PolicyService,
) -> None:
    run = await blocking_service.start(_vm_run_in(CHAT))
    stored = await blocking_service.run(run.id)
    assert stored is not None
    assert stored.conversation == CHAT


@pytest.mark.anyio
async def test_every_journal_row_of_a_run_names_its_conversation(
    blocking_service: PolicyService, journal: CollectingAuditSink
) -> None:
    run = await blocking_service.start(_vm_run_in(CHAT))
    await blocking_service.decide(decision_request(run.id, Capability.FS_READ, WORKDIR_FILE))
    await blocking_service.flush_audit()
    assert [event.conversation for event in journal.events()] == [CHAT]


@pytest.mark.anyio
async def test_a_blocked_conversation_refuses_every_decision(
    blocking_service: PolicyService,
) -> None:
    run = await blocking_service.start(_vm_run_in(CHAT))
    await blocking_service.block_conversation(CHAT, budget=31, by="ads-audit")
    decision = await blocking_service.decide(
        decision_request(run.id, Capability.FS_READ, WORKDIR_FILE)
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "conversation.revoked"
    assert decision.mode is Mode.ENFORCE


@pytest.mark.anyio
async def test_a_new_run_of_a_blocked_conversation_is_refused_too(
    blocking_service: PolicyService,
) -> None:
    first = await blocking_service.start(_vm_run_in(CHAT))
    await blocking_service.block_conversation(CHAT, budget=31, by="ads-audit")
    await blocking_service.finish(first.id)
    second = await blocking_service.start(_vm_run_in(CHAT))
    assert second.state is RunState.RUNNING
    decision = await blocking_service.decide(
        decision_request(second.id, Capability.FS_READ, WORKDIR_FILE)
    )
    assert decision.rule_id == "conversation.revoked"


@pytest.mark.anyio
async def test_blocking_one_conversation_leaves_the_others_alone(
    blocking_service: PolicyService,
) -> None:
    run = await blocking_service.start(_vm_run_in(OTHER_CHAT))
    await blocking_service.block_conversation(CHAT, budget=31, by="ads-audit")
    decision = await blocking_service.decide(
        decision_request(run.id, Capability.FS_READ, WORKDIR_FILE)
    )
    assert decision.effect is Effect.ALLOW


@pytest.mark.anyio
async def test_a_run_without_a_conversation_is_not_affected_by_blocks(
    blocking_service: PolicyService,
) -> None:
    run = await blocking_service.start(run_request(IsolationLevel.VM))
    await blocking_service.block_conversation(CHAT, budget=31, by="ads-audit")
    decision = await blocking_service.decide(
        decision_request(run.id, Capability.FS_READ, WORKDIR_FILE)
    )
    assert decision.effect is Effect.ALLOW


@pytest.mark.anyio
async def test_blocking_twice_is_harmless(blocks: ConversationBlocks) -> None:
    await blocks.block(_block_of(CHAT, budget=31))
    await blocks.block(_block_of(CHAT, budget=40))
    assert await blocks.is_blocked(CHAT)
    assert not await blocks.is_blocked(OTHER_CHAT)
    assert not await blocks.is_blocked("")


@pytest.mark.anyio
async def test_a_block_in_redis_keeps_its_first_record_and_never_expires(redis: Redis) -> None:
    blocks = RedisConversationBlocks(redis)
    await blocks.block(_block_of(CHAT, budget=31))
    await blocks.block(_block_of(CHAT, budget=40))
    key = f"{BLOCK_PREFIX}{CHAT}"
    stored = msgspec.json.decode(await redis.get(key), type=ConversationBlock)
    assert stored.budget == 31
    assert await redis.ttl(key) == -1


@pytest.fixture
def api(tmp_path: Path, redis: Redis) -> Iterator[TestClient]:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    settings = Settings(
        api_token=TOKEN,
        tls_cert_path=cert,
        tls_key_path=key,
        redis_url="redis://unused",
        amqp_url="amqp://unused",
        governance=GovernanceSettings(policy_dir=tmp_path / "missing"),
    )
    with TestClient(app=create_app(settings, redis, CollectingAuditSink())) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        yield client


def test_the_api_blocks_a_conversation(api: TestClient) -> None:
    opened = api.post("/policy/runs", content=msgspec.json.encode(_vm_run_in(CHAT))).json()
    blocked = api.post(
        f"/policy/conversations/{CHAT}/revoke", json={"budget": 31, "by": "ads-audit"}
    )
    assert blocked.status_code == 204
    decision = api.post(
        "/policy/decide",
        content=msgspec.json.encode(
            decision_request(opened["id"], Capability.FS_READ, WORKDIR_FILE)
        ),
    ).json()
    assert decision["rule_id"] == "conversation.revoked"


def test_the_api_refuses_an_unreadable_conversation(api: TestClient) -> None:
    refused = api.post(
        "/policy/conversations/not%20a%20chat/revoke", json={"budget": 31, "by": "ads-audit"}
    )
    assert refused.status_code == 400


def test_a_run_request_with_an_unreadable_conversation_is_refused(api: TestClient) -> None:
    body = msgspec.to_builtins(run_request(IsolationLevel.VM))
    body["conversation"] = "a b"
    assert api.post("/policy/runs", json=body).status_code == 400
