from __future__ import annotations

from dataclasses import replace

import pytest

from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient, UnconfiguredPolicyClient
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    Effect,
    InterceptionPoint,
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
        supervisor.permit("opencode", "read", {"filePath": WORKDIR_FILE})


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
    decision = supervisor.permit("opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.effect is Effect.ALLOW
    assert decision.permitted


def test_a_denied_tool_call_tells_the_agent_nothing_useful(supervisor: Supervisor) -> None:
    supervisor.open()
    decision = supervisor.permit("opencode", "read", {"filePath": "/etc/shadow"})
    assert decision.effect is Effect.DENY
    assert decision.message == GOVERNANCE.denied_message
    assert Capability.FS_READ.value not in decision.message
    for level in IsolationLevel:
        assert level.value not in decision.message


def test_the_supervisor_does_not_inspect_the_call(supervisor: Supervisor) -> None:
    """It forwards the tool call verbatim; both what it means and the verdict are the
    policy service's to decide."""
    supervisor.open()
    for command in ("rm -rf /workspace", "uv sync"):
        decision = supervisor.permit("opencode", "bash", {"command": command})
        assert decision.effect is Effect.ALLOW


def test_a_tool_nothing_binds_is_refused(supervisor: Supervisor) -> None:
    """An agent that grew a new tool does not get it for free."""
    supervisor.open()
    decision = supervisor.permit("opencode", "telepathy", {"thought": "rm -rf /"})
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "binding.missing"


def test_a_call_missing_the_argument_it_acts_on_is_refused(supervisor: Supervisor) -> None:
    supervisor.open()
    decision = supervisor.permit("opencode", "read", {"somethingElse": "/x"})
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "binding.resource"


def test_the_decision_says_what_the_call_turned_out_to_be(supervisor: Supervisor) -> None:
    """The caller asked by tool name, so it learns what that was recognised as."""
    supervisor.open()
    decision = supervisor.permit("opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.capability is Capability.FS_READ
    assert decision.resource == WORKDIR_FILE


@pytest.mark.anyio
async def test_an_answered_call_is_journalled_once_by_the_policy_service(
    supervisor: Supervisor, journal: CollectingAuditSink
) -> None:
    """A second copy from this side would read as a retry and charge the budget twice."""
    supervisor.open()
    supervisor.permit("opencode", "read", {"filePath": WORKDIR_FILE})
    supervisor.permit("opencode", "read", {"filePath": "/etc/shadow"})
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
    decision = supervisor.permit("opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.rule_id == "policy.unreachable"
    assert await supervisor.flush_audit() == 1
    assert journal.events()[-1].rule_id == "policy.unreachable"


def test_a_credential_in_the_arguments_turns_a_permission_into_a_refusal(
    supervisor: Supervisor,
) -> None:
    """The matrix allows the call; what it would carry out of the boundary does not."""
    supervisor.open()
    decision = supervisor.permit(
        "opencode",
        "webfetch",
        {"url": "mirror.interlab", "body": "AWS_KEY=AKIAQYLPMN5HHHFPZAM2"},
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "payload.leak"
    assert decision.point is InterceptionPoint.REQUEST
    assert decision.weight == GOVERNANCE.leak_weight
    assert decision.message == GOVERNANCE.denied_message


def test_clean_arguments_leave_the_permission_alone(supervisor: Supervisor) -> None:
    supervisor.open()
    decision = supervisor.permit(
        "opencode", "webfetch", {"url": "mirror.interlab", "body": "GET /simple/litestar"}
    )
    assert decision.effect is Effect.ALLOW
    assert decision.point is InterceptionPoint.CALL


def test_a_refused_call_is_never_read_for_a_payload(supervisor: Supervisor) -> None:
    """Nothing is sent, so there is no outbound payload; the matrix answer stands."""
    supervisor.open()
    decision = supervisor.permit(
        "opencode", "read", {"filePath": "/etc/shadow", "body": "AKIAQYLPMN5HHHFPZAM2"}
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "fs.read.outside"
    assert decision.point is InterceptionPoint.CALL


@pytest.mark.anyio
async def test_a_leak_is_journalled_here_because_the_policy_service_never_saw_it(
    supervisor: Supervisor, journal: CollectingAuditSink
) -> None:
    supervisor.open()
    supervisor.permit(
        "opencode", "webfetch", {"url": "mirror.interlab", "body": "AWS_KEY=AKIAQYLPMN5HHHFPZAM2"}
    )
    assert await supervisor.flush_audit() == 1
    event = journal.events()[-1]
    assert event.rule_id == "payload.leak"
    assert event.point is InterceptionPoint.REQUEST
    assert event.capability is Capability.NET_EGRESS
    assert event.weight == GOVERNANCE.leak_weight


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
    decision = supervisor.permit("opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.effect is Effect.DENY
    assert decision.enforced
    assert journal.events() == ()
