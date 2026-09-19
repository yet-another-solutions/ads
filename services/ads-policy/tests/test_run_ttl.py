from __future__ import annotations

import anyio
import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.contract import Capability, Effect, IsolationLevel, Run, RunState
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.run import KEY_PREFIX, RedisRunStore
from ads_policy.service import PolicyService
from policy_helpers import decision_request, run_context, run_request

pytestmark = pytest.mark.anyio

TTL = 900


class _UnreachableStore(RedisRunStore):
    async def get(self, run_id: str) -> Run | None:
        raise RedisConnectionError("no route to the run store")


@pytest.fixture
def store(redis: Redis) -> RedisRunStore:
    return RedisRunStore(redis, TTL)


async def _start(store: RedisRunStore, pdp: PolicyDecisionPoint) -> str:
    run = await store.start(
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.VM,
        policy_hash=pdp.policy_hash,
        run_id="run-1",
    )
    return run.id


async def test_a_started_run_carries_the_configured_lifetime(
    store: RedisRunStore, redis: Redis, pdp: PolicyDecisionPoint
) -> None:
    run_id = await _start(store, pdp)
    assert await redis.ttl(f"{KEY_PREFIX}{run_id}") == TTL


async def test_a_forgotten_run_stops_existing(
    store: RedisRunStore, redis: Redis, pdp: PolicyDecisionPoint
) -> None:
    run_id = await _start(store, pdp)
    assert await store.get(run_id) is not None
    await redis.pexpire(f"{KEY_PREFIX}{run_id}", 1)
    await _wait_gone(redis, f"{KEY_PREFIX}{run_id}")
    assert await store.get(run_id) is None


async def test_a_run_past_its_lifetime_decides_nothing(
    redis: Redis,
    pdp: PolicyDecisionPoint,
    audit: BufferedAuditSink,
    journal: CollectingAuditSink,
) -> None:
    service = PolicyService(pdp, RedisRunStore(redis), audit)
    run = await service.start(run_request(IsolationLevel.VM))
    request = decision_request(run.id, Capability.DB_QUERY, "select 1")
    assert (await service.decide(request)).effect is Effect.ALLOW
    await redis.pexpire(f"{KEY_PREFIX}{run.id}", 1)
    await _wait_gone(redis, f"{KEY_PREFIX}{run.id}")
    decision = await service.decide(request)
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "run.unknown"
    await service.flush_audit()
    assert journal.events()[-1].rule_id == "run.unknown"


async def test_revocation_keeps_the_remaining_lifetime(
    store: RedisRunStore, redis: Redis, pdp: PolicyDecisionPoint
) -> None:
    run_id = await _start(store, pdp)
    revoked = await store.revoke(run_id)
    assert revoked.state is RunState.REVOKED
    assert 0 < await redis.ttl(f"{KEY_PREFIX}{run_id}") <= TTL


def _service(redis: Redis, pdp: PolicyDecisionPoint, audit: BufferedAuditSink) -> PolicyService:
    return PolicyService(pdp, RedisRunStore(redis, TTL), audit)


async def test_a_run_in_use_does_not_run_out(
    redis: Redis, pdp: PolicyDecisionPoint, audit: BufferedAuditSink
) -> None:
    service = _service(redis, pdp, audit)
    run = await service.start(run_request(IsolationLevel.VM))
    await redis.expire(f"{KEY_PREFIX}{run.id}", 5)
    await service.decide(decision_request(run.id, Capability.DB_QUERY, "select 1"))
    assert await redis.ttl(f"{KEY_PREFIX}{run.id}") == TTL


async def test_a_refusal_is_use_too(
    redis: Redis, pdp: PolicyDecisionPoint, audit: BufferedAuditSink
) -> None:
    service = _service(redis, pdp, audit)
    run = await service.start(run_request(IsolationLevel.VM))
    await redis.expire(f"{KEY_PREFIX}{run.id}", 5)
    decision = await service.decide(decision_request(run.id, Capability.SECRET_READ, "token"))
    assert decision.effect is Effect.DENY
    assert await redis.ttl(f"{KEY_PREFIX}{run.id}") == TTL


async def test_use_keeps_the_holder_s_index_too(
    redis: Redis, pdp: PolicyDecisionPoint, audit: BufferedAuditSink
) -> None:
    service = _service(redis, pdp, audit)
    run = await service.start(run_request(IsolationLevel.VM, holder="user:alice"))
    await redis.expire("ads:holder:user:alice", 5)
    await service.decide(decision_request(run.id, Capability.DB_QUERY, "select 1"))
    assert await redis.ttl("ads:holder:user:alice") == TTL


@pytest.mark.parametrize("end", ["revoke", "finish"])
async def test_an_ended_run_is_not_kept_alive_by_calls_into_it(
    redis: Redis, pdp: PolicyDecisionPoint, audit: BufferedAuditSink, end: str
) -> None:
    service = _service(redis, pdp, audit)
    run = await service.start(run_request(IsolationLevel.VM))
    await getattr(service, end)(run.id)
    await redis.expire(f"{KEY_PREFIX}{run.id}", 5)
    await service.decide(decision_request(run.id, Capability.DB_QUERY, "select 1"))
    assert await redis.ttl(f"{KEY_PREFIX}{run.id}") <= 5


async def test_a_lifetime_that_cannot_be_extended_does_not_refuse_the_call(
    redis: Redis, pdp: PolicyDecisionPoint, audit: BufferedAuditSink
) -> None:
    class _NoExpiry(RedisRunStore):
        async def touch(self, run: Run) -> None:
            raise RedisConnectionError("no route to the run store")

    service = PolicyService(pdp, _NoExpiry(redis), audit)
    run = await service.start(run_request(IsolationLevel.VM))
    decision = await service.decide(decision_request(run.id, Capability.DB_QUERY, "select 1"))
    assert decision.effect is Effect.ALLOW


async def test_a_second_replica_sees_the_same_runs(redis: Redis, pdp: PolicyDecisionPoint) -> None:
    first = RedisRunStore(redis)
    second = RedisRunStore(redis)
    run = await first.start(
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.VM,
        policy_hash=pdp.policy_hash,
    )
    assert await second.get(run.id) == run
    await second.revoke(run.id)
    seen = await first.get(run.id)
    assert seen is not None
    assert seen.state is RunState.REVOKED


async def test_runs_are_namespaced_in_the_keyspace(
    store: RedisRunStore, redis: Redis, pdp: PolicyDecisionPoint
) -> None:
    run_id = await _start(store, pdp)
    assert await redis.keys("*") == [f"{KEY_PREFIX}{run_id}".encode()]


async def test_an_unreachable_store_denies(
    redis: Redis,
    pdp: PolicyDecisionPoint,
    audit: BufferedAuditSink,
    journal: CollectingAuditSink,
) -> None:
    service = PolicyService(pdp, _UnreachableStore(redis), audit)
    decision = await service.decide(decision_request("run-1", Capability.DB_QUERY, "select 1"))
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "run.store"
    assert decision.enforced
    await service.flush_audit()
    assert journal.events()[-1].rule_id == "run.store"


async def _wait_gone(redis: Redis, key: str) -> None:
    for _ in range(100):
        if not await redis.exists(key):
            return
        await anyio.sleep(0.01)
    raise AssertionError(f"{key} never expired")
