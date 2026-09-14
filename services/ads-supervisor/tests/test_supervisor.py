from __future__ import annotations

from dataclasses import replace

import pytest

from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient, UnconfiguredPolicyClient
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    Effect,
    IsolationLevel,
    Placement,
    Run,
    RunContext,
)
from ads_supervisor.config import Settings
from ads_supervisor.supervisor import RunNotOpen, Supervisor
from supervisor_helpers import RefusingPolicyClient

GOVERNANCE = GovernanceSettings()
WORKDIR_FILE = f"{GOVERNANCE.workdir}/src/app.py"


def test_a_run_is_opened_before_anything_is_permitted(supervisor: Supervisor) -> None:
    assert supervisor.run is None
    with pytest.raises(RunNotOpen):
        supervisor.permit(Capability.FS_READ, WORKDIR_FILE)


def test_the_run_takes_its_level_from_the_placement(supervisor: Supervisor) -> None:
    run = supervisor.open()
    assert run.isolation_level is IsolationLevel.VM
    assert run.subject == "alice"
    assert supervisor.run == run


def test_a_workstation_run_is_local(
    settings: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> None:
    local = replace(settings, placement=Placement.WORKSTATION, node_labels={})
    supervisor = Supervisor(settings=local, client=policy_client, audit=audit)
    assert supervisor.open().isolation_level is IsolationLevel.LOCAL


def test_a_permitted_tool_call_comes_back_allowed(supervisor: Supervisor) -> None:
    supervisor.open()
    decision = supervisor.permit(Capability.FS_READ, WORKDIR_FILE)
    assert decision.effect is Effect.ALLOW
    assert decision.permitted


def test_a_denied_tool_call_tells_the_agent_nothing_useful(supervisor: Supervisor) -> None:
    supervisor.open()
    decision = supervisor.permit(Capability.SECRET_READ, "ads-client-secret")
    assert decision.effect is Effect.DENY
    assert decision.message == GOVERNANCE.denied_message
    assert Capability.SECRET_READ.value not in decision.message
    for level in IsolationLevel:
        assert level.value not in decision.message


def test_the_supervisor_does_not_inspect_the_call(supervisor: Supervisor) -> None:
    """Naming the capability is all it does; the verdict belongs to the policy service."""
    supervisor.open()
    for command in ("rm -rf /workspace", "uv sync"):
        assert supervisor.permit(Capability.PROCESS_EXEC, command).effect is Effect.ALLOW


@pytest.mark.anyio
async def test_an_answered_call_is_journalled_once_by_the_policy_service(
    supervisor: Supervisor, journal: CollectingAuditSink
) -> None:
    """A second copy from this side would read as a retry and charge the budget twice."""
    supervisor.open()
    supervisor.permit(Capability.FS_READ, WORKDIR_FILE)
    supervisor.permit(Capability.SECRET_READ, "ads-client-secret")
    assert await supervisor.flush_audit() == 0
    assert journal.events() == ()


@pytest.mark.anyio
async def test_a_call_the_policy_service_never_saw_is_journalled_here(
    settings: Settings, audit: BufferedAuditSink, journal: CollectingAuditSink
) -> None:
    """Otherwise a break in the network quietly erases that stretch of history."""
    supervisor = Supervisor(
        settings=settings,
        client=UnconfiguredPolicyClient(GOVERNANCE.denied_message),
        audit=audit,
        run=Run(
            id="run-1",
            subject="alice",
            context=RunContext(project="ads", repo="ads", env="dev", workdir=GOVERNANCE.workdir),
            isolation_level=IsolationLevel.VM,
            policy_hash="deadbeef",
        ),
    )
    decision = supervisor.permit(Capability.FS_READ, WORKDIR_FILE)
    assert decision.rule_id == "policy.unreachable"
    assert await supervisor.flush_audit() == 1
    assert journal.events()[-1].rule_id == "policy.unreachable"


def test_an_unreachable_policy_service_opens_no_run(
    settings: Settings, audit: BufferedAuditSink
) -> None:
    supervisor = Supervisor(settings=settings, client=RefusingPolicyClient(), audit=audit)
    with pytest.raises(ConnectionError):
        supervisor.open()


def test_a_full_backlog_never_turns_a_refusal_into_a_pass(
    settings: Settings, journal: CollectingAuditSink
) -> None:
    """The record of this one is lost, but nothing was granted, which is the point."""
    full = BufferedAuditSink(journal, GovernanceSettings(audit_backlog=0))
    supervisor = Supervisor(
        settings=settings,
        client=UnconfiguredPolicyClient(GOVERNANCE.denied_message),
        audit=full,
        run=Run(
            id="run-1",
            subject="alice",
            context=RunContext(project="ads", repo="ads", env="dev", workdir=GOVERNANCE.workdir),
            isolation_level=IsolationLevel.VM,
            policy_hash="deadbeef",
        ),
    )
    decision = supervisor.permit(Capability.FS_READ, WORKDIR_FILE)
    assert decision.effect is Effect.DENY
    assert decision.enforced
    assert journal.events() == ()
