from __future__ import annotations

import pytest

from ads_policy.contract import (
    Capability,
    Effect,
    IsolationLevel,
    Run,
    RunState,
    ToolCallRequest,
)
from ads_policy.run import RunStore
from ads_policy.service import PolicyService
from policy_helpers import decision_request, run_context

pytestmark = pytest.mark.anyio

LOST_POLICY_HASH = "deadbeef"


async def _run_under_a_lost_policy(runs: RunStore) -> Run:
    return await runs.start(
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.VM,
        policy_hash=LOST_POLICY_HASH,
    )


async def test_a_decision_in_a_run_whose_policy_is_gone_finishes_the_run(
    service: PolicyService, runs: RunStore
) -> None:
    run = await _run_under_a_lost_policy(runs)
    decision = await service.decide(
        decision_request(run.id, Capability.FS_READ, "/workspace/README.md")
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "policy.missing"
    finished = await runs.get(run.id)
    assert finished is not None
    assert finished.state is RunState.FINISHED


async def test_a_tool_call_in_a_run_whose_policy_is_gone_finishes_the_run(
    service: PolicyService, runs: RunStore
) -> None:
    run = await _run_under_a_lost_policy(runs)
    decision = await service.decide_call(
        ToolCallRequest(
            run_id=run.id,
            subject="alice",
            source="opencode",
            tool="read",
            arguments={"filePath": "/workspace/README.md"},
        )
    )
    assert decision.rule_id == "policy.missing"
    finished = await runs.get(run.id)
    assert finished is not None
    assert finished.state is RunState.FINISHED


async def test_a_revoked_run_whose_policy_is_gone_stays_revoked(
    service: PolicyService, runs: RunStore
) -> None:
    run = await _run_under_a_lost_policy(runs)
    await runs.revoke(run.id)
    await service.decide(decision_request(run.id, Capability.FS_READ, "/workspace/README.md"))
    revoked = await runs.get(run.id)
    assert revoked is not None
    assert revoked.state is RunState.REVOKED
