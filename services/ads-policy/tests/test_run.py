from __future__ import annotations

import pytest

from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    Effect,
    IsolationLevel,
    Mode,
    Run,
    RunState,
)
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy
from ads_policy.run import RunStore
from policy_helpers import policy_request, run_context

pytestmark = pytest.mark.anyio


async def _start(store: RunStore, pdp: PolicyDecisionPoint, run_id: str = "run-1") -> Run:
    return await store.start(
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.VM,
        policy_hash=pdp.policy_hash,
        run_id=run_id,
    )


def test_run_carries_the_agreed_fields_and_no_stored_counter() -> None:
    assert Run.__struct_fields__ == (
        "id",
        "subject",
        "context",
        "isolation_level",
        "policy_hash",
        "state",
        "holder",
        "conversation",
    )


async def test_one_session_yields_many_runs(runs: RunStore, pdp: PolicyDecisionPoint) -> None:
    first = await runs.start(
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.VM,
        policy_hash=pdp.policy_hash,
    )
    second = await runs.start(
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.CONTAINER,
        policy_hash=pdp.policy_hash,
    )
    assert first.id != second.id
    assert first.subject == second.subject


async def test_a_started_run_is_readable_back(runs: RunStore, pdp: PolicyDecisionPoint) -> None:
    started = await _start(runs, pdp)
    assert await runs.get(started.id) == started
    assert await runs.get("nope") is None


async def test_the_policy_version_is_pinned_at_start(
    runs: RunStore, pdp: PolicyDecisionPoint
) -> None:
    run = await _start(runs, pdp)
    pinned = pdp.policy_hash
    tightened = org_policy(GovernanceSettings(rules=(), policy_version="org-2"))
    pdp.reload(tightened)
    assert run.policy_hash == pinned
    assert pdp.policy_hash != pinned
    request = policy_request(Capability.DB_QUERY, "select 1", level=IsolationLevel.VM)
    assert pdp.decide_for_run(run, request).effect is Effect.ALLOW
    assert pdp.decide(request).effect is Effect.DENY


async def test_revocation_is_visible_on_the_next_request(
    runs: RunStore, pdp: PolicyDecisionPoint
) -> None:
    run = await _start(runs, pdp)
    request = policy_request(Capability.DB_QUERY, "select 1", level=IsolationLevel.VM)
    assert pdp.decide_for_run(run, request).effect is Effect.ALLOW
    revoked = await runs.revoke(run.id)
    assert revoked.state is RunState.REVOKED
    assert (await runs.get(run.id)) == revoked
    decision = pdp.decide_for_run(revoked, request)
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "run.state"


async def test_revocation_applies_even_in_review_mode(runs: RunStore) -> None:
    watching = PolicyDecisionPoint(org_policy(GovernanceSettings(mode=Mode.REVIEW)))
    run = await _start(runs, watching)
    revoked = await runs.revoke(run.id)
    decision = watching.decide_for_run(
        revoked, policy_request(Capability.DB_QUERY, "select 1", level=IsolationLevel.VM)
    )
    assert decision.mode is Mode.ENFORCE
    assert not decision.permitted


async def test_a_finished_run_decides_nothing_more(
    runs: RunStore, pdp: PolicyDecisionPoint
) -> None:
    run = await _start(runs, pdp)
    finished = await runs.finish(run.id)
    assert finished.state is RunState.FINISHED
    decision = pdp.decide_for_run(
        finished, policy_request(Capability.DB_QUERY, "select 1", level=IsolationLevel.VM)
    )
    assert decision.effect is Effect.DENY


async def test_a_pinned_policy_that_is_gone_denies(
    runs: RunStore, pdp: PolicyDecisionPoint
) -> None:
    run = await runs.start(
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.VM,
        policy_hash="deadbeef",
    )
    decision = pdp.decide_for_run(
        run, policy_request(Capability.DB_QUERY, "select 1", level=IsolationLevel.VM)
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "policy.missing"


async def test_an_unknown_run_cannot_be_moved(runs: RunStore) -> None:
    with pytest.raises(KeyError):
        await runs.revoke("nope")
