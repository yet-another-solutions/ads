from __future__ import annotations

import msgspec
import pytest

from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient, UnconfiguredPolicyClient
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    Effect,
    InterceptionPoint,
    IsolationLevel,
)
from ads_policy.isolation import UnknownPlacement
from ads_supervisor.config import Settings
from ads_supervisor.supervisor import RunNotOpen, Supervisor
from supervisor_helpers import VM_SANDBOX, WORKSTATION, RefusingPolicyClient

GOVERNANCE = GovernanceSettings()
WORKDIR_FILE = f"{GOVERNANCE.workdir}/src/app.py"


def test_a_call_without_a_run_is_refused(supervisor: Supervisor) -> None:
    """One process serves many runs, so the call has to say which one it belongs to."""
    with pytest.raises(RunNotOpen):
        supervisor.permit("", "opencode", "read", {"filePath": WORKDIR_FILE})


def test_the_run_takes_its_level_from_the_sandbox_it_was_opened_for(
    supervisor: Supervisor,
) -> None:
    run = supervisor.open(VM_SANDBOX)
    assert run.isolation_level is IsolationLevel.VM
    assert run.subject == "alice"


def test_one_service_serves_agents_in_different_sandboxes(supervisor: Supervisor) -> None:
    """It stands outside all of them, so its own placement says nothing about theirs."""
    assert supervisor.open(WORKSTATION).isolation_level is IsolationLevel.LOCAL
    assert supervisor.open(VM_SANDBOX).isolation_level is IsolationLevel.VM


def test_a_sandbox_that_is_not_what_it_claims_opens_no_run(supervisor: Supervisor) -> None:
    """A Kata runtime class on a node nobody labelled is refused, not downgraded."""
    unlabelled = msgspec.structs.replace(VM_SANDBOX, node_labels={})
    with pytest.raises(UnknownPlacement):
        supervisor.open(unlabelled)


def test_one_process_serves_many_runs(supervisor: Supervisor) -> None:
    """The agent is a long-lived worker: task after task off a queue, one process."""
    first = supervisor.open(VM_SANDBOX)
    second = supervisor.open(VM_SANDBOX)
    assert first.id != second.id
    for run in (first, second):
        decision = supervisor.permit(run.id, "opencode", "read", {"filePath": WORKDIR_FILE})
        assert decision.effect is Effect.ALLOW


def test_a_permitted_tool_call_comes_back_allowed(supervisor: Supervisor, run_id: str) -> None:
    decision = supervisor.permit(run_id, "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.effect is Effect.ALLOW
    assert decision.permitted


def test_a_denied_tool_call_tells_the_agent_nothing_useful(
    supervisor: Supervisor, run_id: str
) -> None:
    decision = supervisor.permit(run_id, "opencode", "read", {"filePath": "/etc/shadow"})
    assert decision.effect is Effect.DENY
    assert decision.message == GOVERNANCE.denied_message
    assert Capability.FS_READ.value not in decision.message
    for level in IsolationLevel:
        assert level.value not in decision.message


def test_the_supervisor_does_not_inspect_the_call(supervisor: Supervisor, run_id: str) -> None:
    """It forwards the tool call verbatim; both what it means and the verdict are the
    policy service's to decide."""
    for command in ("rm -rf /workspace", "uv sync"):
        decision = supervisor.permit(run_id, "opencode", "bash", {"command": command})
        assert decision.effect is Effect.ALLOW


def test_a_tool_nothing_binds_is_refused(supervisor: Supervisor, run_id: str) -> None:
    """An agent that grew a new tool does not get it for free."""
    decision = supervisor.permit(run_id, "opencode", "telepathy", {"thought": "rm -rf /"})
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "binding.missing"


def test_a_call_missing_the_argument_it_acts_on_is_refused(
    supervisor: Supervisor, run_id: str
) -> None:
    decision = supervisor.permit(run_id, "opencode", "read", {"somethingElse": "/x"})
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "binding.resource"


def test_the_decision_says_what_the_call_turned_out_to_be(
    supervisor: Supervisor, run_id: str
) -> None:
    """The caller asked by tool name, so it learns what that was recognised as."""
    decision = supervisor.permit(run_id, "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.capability is Capability.FS_READ
    assert decision.resource == WORKDIR_FILE


@pytest.mark.anyio
async def test_an_answered_call_is_journalled_once_by_the_policy_service(
    supervisor: Supervisor, run_id: str, journal: CollectingAuditSink
) -> None:
    """A second copy from this side would read as a retry and charge the budget twice."""
    supervisor.permit(run_id, "opencode", "read", {"filePath": WORKDIR_FILE})
    supervisor.permit(run_id, "opencode", "read", {"filePath": "/etc/shadow"})
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
    )
    decision = supervisor.permit("run-1", "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.rule_id == "policy.unreachable"
    assert await supervisor.flush_audit() == 1
    assert journal.events()[-1].rule_id == "policy.unreachable"


def test_a_credential_in_the_arguments_turns_a_permission_into_a_refusal(
    supervisor: Supervisor, run_id: str
) -> None:
    """The matrix allows the call; what it would carry out of the boundary does not."""
    decision = supervisor.permit(
        run_id,
        "opencode",
        "webfetch",
        {"url": "mirror.interlab", "body": "AWS_KEY=AKIAQYLPMN5HHHFPZAM2"},
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "payload.leak"
    assert decision.point is InterceptionPoint.REQUEST
    assert decision.weight == GOVERNANCE.leak_weight
    assert decision.message == GOVERNANCE.denied_message


def test_clean_arguments_leave_the_permission_alone(supervisor: Supervisor, run_id: str) -> None:
    decision = supervisor.permit(
        run_id, "opencode", "webfetch", {"url": "mirror.interlab", "body": "GET /simple/litestar"}
    )
    assert decision.effect is Effect.ALLOW
    assert decision.point is InterceptionPoint.CALL


def test_a_refused_call_is_never_read_for_a_payload(supervisor: Supervisor, run_id: str) -> None:
    """Nothing is sent, so there is no outbound payload; the matrix answer stands."""
    decision = supervisor.permit(
        run_id, "opencode", "read", {"filePath": "/etc/shadow", "body": "AKIAQYLPMN5HHHFPZAM2"}
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "fs.read.outside"
    assert decision.point is InterceptionPoint.CALL


@pytest.mark.anyio
async def test_a_leak_is_journalled_here_because_the_policy_service_never_saw_it(
    supervisor: Supervisor, run_id: str, journal: CollectingAuditSink
) -> None:
    supervisor.permit(
        run_id,
        "opencode",
        "webfetch",
        {"url": "mirror.interlab", "body": "AWS_KEY=AKIAQYLPMN5HHHFPZAM2"},
    )
    assert await supervisor.flush_audit() == 1
    event = journal.events()[-1]
    assert event.rule_id == "payload.leak"
    assert event.point is InterceptionPoint.REQUEST
    assert event.capability is Capability.NET_EGRESS
    assert event.weight == GOVERNANCE.leak_weight


@pytest.mark.anyio
async def test_a_credential_in_the_result_is_redacted_not_refused(
    supervisor: Supervisor, run_id: str, journal: CollectingAuditSink
) -> None:
    """The call already happened; refusing the answer protects nothing."""
    decision = supervisor.permit(run_id, "opencode", "read", {"filePath": WORKDIR_FILE})
    reading = supervisor.inspect_result(run_id, decision, ["key = AKIAQYLPMN5HHHFPZAM2"])
    assert reading.decision.effect is Effect.TRANSFORM
    assert reading.texts == ("key = [redacted:aws-access-token]",)
    assert await supervisor.flush_audit() == 1
    assert journal.events()[-1].point is InterceptionPoint.RESPONSE


@pytest.mark.anyio
async def test_a_result_of_many_strings_is_one_row(
    supervisor: Supervisor, run_id: str, journal: CollectingAuditSink
) -> None:
    """Each string is read and cleaned on its own; the verdict is the result's."""
    decision = supervisor.permit(run_id, "opencode", "read", {"filePath": WORKDIR_FILE})
    texts = ["clean", "key = AKIAQYLPMN5HHHFPZAM2", "also clean"]
    reading = supervisor.inspect_result(run_id, decision, texts)
    assert reading.texts == ("clean", "key = [redacted:aws-access-token]", "also clean")
    assert await supervisor.flush_audit() == 1


def test_a_lost_row_does_not_become_a_leaked_secret(
    settings: Settings, policy_client: PolicyClient, journal: CollectingAuditSink
) -> None:
    """The backlog is full, so the finding cannot be recorded; the secret is cut anyway."""
    full = BufferedAuditSink(journal, GovernanceSettings(audit_backlog=0))
    supervisor = Supervisor(settings=settings, client=policy_client, audit=full)
    run = supervisor.open(VM_SANDBOX).id
    decision = supervisor.permit(run, "opencode", "read", {"filePath": WORKDIR_FILE})
    reading = supervisor.inspect_result(run, decision, ["key = AKIAQYLPMN5HHHFPZAM2"])
    assert "AKIAQYLPMN5HHHFPZAM2" not in reading.texts[0]


@pytest.mark.anyio
async def test_a_clean_result_is_not_journalled(
    supervisor: Supervisor, run_id: str, journal: CollectingAuditSink
) -> None:
    """A row per untouched tool result would bury the rows that mean something."""
    decision = supervisor.permit(run_id, "opencode", "read", {"filePath": WORKDIR_FILE})
    reading = supervisor.inspect_result(run_id, decision, ["def main() -> None: ..."])
    assert reading.decision.effect is Effect.ALLOW
    assert reading.texts == ("def main() -> None: ...",)
    assert await supervisor.flush_audit() == 0


def test_an_unreachable_policy_service_opens_no_run(
    settings: Settings, audit: BufferedAuditSink
) -> None:
    supervisor = Supervisor(settings=settings, client=RefusingPolicyClient(), audit=audit)
    with pytest.raises(ConnectionError):
        supervisor.open(VM_SANDBOX)


def test_a_full_backlog_never_turns_a_refusal_into_a_pass(
    settings: Settings, journal: CollectingAuditSink
) -> None:
    """The record of this one is lost, but nothing was granted, which is the point."""
    full = BufferedAuditSink(journal, GovernanceSettings(audit_backlog=0))
    supervisor = Supervisor(
        settings=settings,
        client=UnconfiguredPolicyClient(GOVERNANCE.denied_message),
        audit=full,
    )
    decision = supervisor.permit("run-1", "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.effect is Effect.DENY
    assert decision.enforced
    assert journal.events() == ()
