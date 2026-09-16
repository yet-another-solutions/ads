from __future__ import annotations

from dataclasses import replace

import msgspec
import pytest

from ads_guardrail.config import Settings
from ads_guardrail.guardrail import Guardrail, NotAPerson, RunNotOpen, person
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient, UnconfiguredPolicyClient
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    Effect,
    InterceptionPoint,
    IsolationLevel,
    Run,
    RunContext,
)
from ads_policy.isolation import UnknownPlacement
from guardrail_helpers import (
    ALICE,
    BOB,
    FORGING_KEY,
    USER_TOKEN,
    VERIFIER,
    VM_SANDBOX,
    WORKSTATION,
    RefusingPolicyClient,
    opening,
    token,
)

GOVERNANCE = GovernanceSettings()
WORKDIR_FILE = f"{GOVERNANCE.workdir}/src/app.py"

#: A run the policy service never opened, for calls that never reach it.
NOWHERE = Run(
    id="run-1",
    subject="alice",
    context=RunContext(project="ads", repo="ads", env="dev", workdir=GOVERNANCE.workdir),
    isolation_level=IsolationLevel.VM,
    policy_hash="",
)


# --- opening ------------------------------------------------------------------------


def test_the_run_is_opened_for_the_person_the_token_names(guardrail: Guardrail) -> None:
    """Who it is for is read from the verified token, never taken on the caller's word."""
    run = guardrail.open(opening(bearer=token(BOB)))
    assert run.subject == BOB
    assert run.holder == person(BOB)
    assert run.isolation_level is IsolationLevel.VM


def test_the_token_itself_is_not_kept(guardrail: Guardrail) -> None:
    run = guardrail.open(opening())
    assert USER_TOKEN not in msgspec.json.encode(run).decode()


@pytest.mark.parametrize(
    ("bearer", "why"),
    [
        ("not-a-jwt", "does not verify"),
        ("", "does not verify"),
        (token(key=FORGING_KEY), "does not verify"),
        (token(aud="some-other-application"), "does not verify"),
        (token(iss="https://elsewhere.test/realms/ads"), "does not verify"),
        (token(issued=-3600), "does not verify"),
        (token(sub="alice"), "does not verify"),
    ],
    ids=["garbage", "empty", "forged", "other-audience", "other-issuer", "expired", "not-a-uuid"],
)
def test_a_run_is_not_opened_on_a_token_that_does_not_verify(
    guardrail: Guardrail, bearer: str, why: str
) -> None:
    """Anyone can write a token naming anybody; only one Keycloak signed, for us, counts."""
    with pytest.raises(NotAPerson, match=why):
        guardrail.open(opening(bearer=bearer))


def test_without_an_audience_no_person_is_recognised(
    settings: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> None:
    """Otherwise any token of theirs, issued to any application, would act in their runs."""
    unset = Guardrail(
        settings=replace(settings, mcp_audience=""),
        client=policy_client,
        audit=audit,
        verifier=VERIFIER,
    )
    with pytest.raises(NotAPerson, match="no audience"):
        unset.open(opening())


def test_without_a_verifier_no_person_is_recognised(
    settings: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> None:
    unverified = Guardrail(settings=settings, client=policy_client, audit=audit)
    with pytest.raises(NotAPerson):
        unverified.open(opening())


def test_one_service_serves_agents_in_different_sandboxes(guardrail: Guardrail) -> None:
    """It stands outside all of them, so its own placement says nothing about theirs."""
    assert guardrail.open(opening(WORKSTATION)).isolation_level is IsolationLevel.LOCAL
    assert guardrail.open(opening(VM_SANDBOX)).isolation_level is IsolationLevel.VM


def test_a_sandbox_that_is_not_what_it_claims_opens_no_run(guardrail: Guardrail) -> None:
    """A Kata runtime class on a node nobody labelled is refused, not downgraded."""
    unlabelled = msgspec.structs.replace(VM_SANDBOX, node_labels={})
    with pytest.raises(UnknownPlacement):
        guardrail.open(opening(unlabelled))


def test_an_unreachable_policy_service_opens_no_run(
    settings: Settings, audit: BufferedAuditSink
) -> None:
    guardrail = Guardrail(
        settings=settings, client=RefusingPolicyClient(), audit=audit, verifier=VERIFIER
    )
    with pytest.raises(ConnectionError):
        guardrail.open(opening())


# --- finding the run a call belongs to ----------------------------------------------


def test_a_call_is_found_by_the_person_it_comes_from(guardrail: Guardrail) -> None:
    opened = guardrail.open(opening())
    assert guardrail.find(USER_TOKEN).id == opened.id


def test_a_refreshed_token_stays_in_the_same_run(guardrail: Guardrail) -> None:
    """The run is the person's, not the token's: a long task outlives its first token."""
    opened = guardrail.open(opening(bearer=token(ALICE)))
    refreshed = token(ALICE, issued=-60, jti="refreshed")
    assert refreshed != USER_TOKEN
    assert guardrail.find(refreshed).id == opened.id


def test_an_expired_token_finds_nothing(guardrail: Guardrail) -> None:
    """The service refreshes it and carries on; an old one is not honoured meanwhile."""
    guardrail.open(opening())
    with pytest.raises(RunNotOpen, match="does not verify"):
        guardrail.find(token(ALICE, issued=-3600))


def test_a_forged_token_for_a_real_person_finds_nothing(guardrail: Guardrail) -> None:
    guardrail.open(opening())
    with pytest.raises(RunNotOpen, match="does not verify"):
        guardrail.find(token(ALICE, key=FORGING_KEY))


def test_a_call_without_credentials_belongs_to_nothing(guardrail: Guardrail) -> None:
    guardrail.open(opening())
    with pytest.raises(RunNotOpen):
        guardrail.find("")


def test_someone_nobody_opened_a_run_for_belongs_to_nothing(guardrail: Guardrail) -> None:
    guardrail.open(opening())
    with pytest.raises(RunNotOpen, match="no run is open"):
        guardrail.find(token(BOB))


def test_two_runs_of_one_person_have_to_be_told_apart(guardrail: Guardrail) -> None:
    """A person with two sandboxes: the call has to say which one it is for."""
    first = guardrail.open(opening())
    second = guardrail.open(opening())
    with pytest.raises(RunNotOpen, match="name one"):
        guardrail.find(USER_TOKEN)
    assert guardrail.find(USER_TOKEN, second.id).id == second.id
    assert guardrail.find(USER_TOKEN, first.id).id == first.id


def test_a_named_run_has_to_be_the_caller_s_own(guardrail: Guardrail) -> None:
    """A run id alone is not a credential."""
    theirs = guardrail.open(opening(bearer=token(BOB)))
    guardrail.open(opening())
    with pytest.raises(RunNotOpen, match="not its own"):
        guardrail.find(USER_TOKEN, theirs.id)


def test_a_revoked_run_is_still_found_so_the_refusal_is_journalled(
    guardrail: Guardrail, policy_client: PolicyClient
) -> None:
    """Refusing here would leave no row; the policy service refuses it and writes one."""
    run = guardrail.open(opening())
    policy_client.revoke_run(run.id)
    found = guardrail.find(USER_TOKEN)
    assert found.id == run.id
    decision = guardrail.permit(found, "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.rule_id == "run.state"


def test_the_next_task_is_found_once_the_last_is_finished(guardrail: Guardrail) -> None:
    """Without finishing, the same token would hold two runs and have to name one."""
    first = guardrail.open(opening())
    guardrail.finish(first.id)
    second = guardrail.open(opening())
    assert guardrail.find(USER_TOKEN).id == second.id


def test_finishing_an_unknown_run_says_so(guardrail: Guardrail) -> None:
    assert guardrail.finish("never-opened") is None


def test_finishing_needs_the_policy_service(settings: Settings, audit: BufferedAuditSink) -> None:
    guardrail = Guardrail(settings=settings, client=RefusingPolicyClient(), audit=audit)
    with pytest.raises(RunNotOpen):
        guardrail.finish("run-1")


def test_an_unreachable_policy_service_finds_nothing(
    settings: Settings, audit: BufferedAuditSink
) -> None:
    guardrail = Guardrail(
        settings=settings, client=RefusingPolicyClient(), audit=audit, verifier=VERIFIER
    )
    with pytest.raises(RunNotOpen, match="cannot be looked up"):
        guardrail.find(USER_TOKEN)


def test_the_decision_api_names_its_run_directly(guardrail: Guardrail, run: Run) -> None:
    """Its caller holds the API token, so no credentials of the run are asked for."""
    assert guardrail.run(run.id).id == run.id
    with pytest.raises(RunNotOpen):
        guardrail.run("")
    with pytest.raises(RunNotOpen):
        guardrail.run("never-opened")


# --- deciding -----------------------------------------------------------------------


def test_one_process_serves_many_runs(guardrail: Guardrail) -> None:
    """The agent is a long-lived worker: task after task off a queue, one process."""
    first = guardrail.open(opening())
    second = guardrail.open(opening(bearer=token(BOB)))
    assert first.id != second.id
    for run in (first, second):
        decision = guardrail.permit(run, "opencode", "read", {"filePath": WORKDIR_FILE})
        assert decision.effect is Effect.ALLOW


def test_a_permitted_tool_call_comes_back_allowed(guardrail: Guardrail, run: Run) -> None:
    decision = guardrail.permit(run, "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.effect is Effect.ALLOW
    assert decision.permitted


def test_a_revoked_run_is_refused_by_the_policy_service(
    guardrail: Guardrail, run: Run, policy_client: PolicyClient
) -> None:
    """Its state is judged there, where the refusal is journalled."""
    policy_client.revoke_run(run.id)
    decision = guardrail.permit(guardrail.run(run.id), "opencode", "read", {"filePath": "x"})
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "run.state"


def test_a_denied_tool_call_tells_the_agent_nothing_useful(guardrail: Guardrail, run: Run) -> None:
    decision = guardrail.permit(run, "opencode", "read", {"filePath": "/etc/shadow"})
    assert decision.effect is Effect.DENY
    assert decision.message == GOVERNANCE.denied_message
    assert Capability.FS_READ.value not in decision.message
    for level in IsolationLevel:
        assert level.value not in decision.message


def test_the_guardrail_does_not_inspect_the_call(guardrail: Guardrail, run: Run) -> None:
    """It forwards the tool call verbatim; both what it means and the verdict are the
    policy service's to decide."""
    for command in ("rm -rf /workspace", "uv sync"):
        decision = guardrail.permit(run, "opencode", "bash", {"command": command})
        assert decision.effect is Effect.ALLOW


def test_a_tool_nothing_binds_is_refused(guardrail: Guardrail, run: Run) -> None:
    """An agent that grew a new tool does not get it for free."""
    decision = guardrail.permit(run, "opencode", "telepathy", {"thought": "rm -rf /"})
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "binding.missing"


def test_a_call_missing_the_argument_it_acts_on_is_refused(guardrail: Guardrail, run: Run) -> None:
    decision = guardrail.permit(run, "opencode", "read", {"somethingElse": "/x"})
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "binding.resource"


def test_the_decision_says_what_the_call_turned_out_to_be(guardrail: Guardrail, run: Run) -> None:
    """The caller asked by tool name, so it learns what that was recognised as."""
    decision = guardrail.permit(run, "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.capability is Capability.FS_READ
    assert decision.resource == WORKDIR_FILE


@pytest.mark.anyio
async def test_an_answered_call_is_journalled_once_by_the_policy_service(
    guardrail: Guardrail, run: Run, journal: CollectingAuditSink
) -> None:
    """A second copy from this side would read as a retry and charge the budget twice."""
    guardrail.permit(run, "opencode", "read", {"filePath": WORKDIR_FILE})
    guardrail.permit(run, "opencode", "read", {"filePath": "/etc/shadow"})
    assert await guardrail.flush_audit() == 0
    assert journal.events() == ()


@pytest.mark.anyio
async def test_a_call_the_policy_service_never_saw_is_journalled_here(
    settings: Settings, audit: BufferedAuditSink, journal: CollectingAuditSink
) -> None:
    """Otherwise a break in the network quietly erases that stretch of history."""
    guardrail = Guardrail(
        settings=settings,
        client=UnconfiguredPolicyClient(GOVERNANCE.denied_message),
        audit=audit,
    )
    decision = guardrail.permit(NOWHERE, "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.rule_id == "policy.unreachable"
    assert await guardrail.flush_audit() == 1
    event = journal.events()[-1]
    assert event.rule_id == "policy.unreachable"
    assert event.subject == "alice"


def test_a_credential_in_the_arguments_turns_a_permission_into_a_refusal(
    guardrail: Guardrail, run: Run
) -> None:
    """The matrix allows the call; what it would carry out of the boundary does not."""
    decision = guardrail.permit(
        run,
        "opencode",
        "webfetch",
        {"url": "mirror.interlab", "body": "AWS_KEY=AKIAQYLPMN5HHHFPZAM2"},
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "payload.leak"
    assert decision.point is InterceptionPoint.REQUEST
    assert decision.weight == GOVERNANCE.leak_weight
    assert decision.message == GOVERNANCE.denied_message


def test_clean_arguments_leave_the_permission_alone(guardrail: Guardrail, run: Run) -> None:
    decision = guardrail.permit(
        run, "opencode", "webfetch", {"url": "mirror.interlab", "body": "GET /simple/litestar"}
    )
    assert decision.effect is Effect.ALLOW
    assert decision.point is InterceptionPoint.CALL


def test_a_refused_call_is_never_read_for_a_payload(guardrail: Guardrail, run: Run) -> None:
    """Nothing is sent, so there is no outbound payload; the matrix answer stands."""
    decision = guardrail.permit(
        run, "opencode", "read", {"filePath": "/etc/shadow", "body": "AKIAQYLPMN5HHHFPZAM2"}
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "fs.read.outside"
    assert decision.point is InterceptionPoint.CALL


@pytest.mark.anyio
async def test_a_leak_is_journalled_here_because_the_policy_service_never_saw_it(
    guardrail: Guardrail, run: Run, journal: CollectingAuditSink
) -> None:
    guardrail.permit(
        run,
        "opencode",
        "webfetch",
        {"url": "mirror.interlab", "body": "AWS_KEY=AKIAQYLPMN5HHHFPZAM2"},
    )
    assert await guardrail.flush_audit() == 1
    event = journal.events()[-1]
    assert event.rule_id == "payload.leak"
    assert event.point is InterceptionPoint.REQUEST
    assert event.capability is Capability.NET_EGRESS
    assert event.weight == GOVERNANCE.leak_weight
    assert event.subject == run.subject


# --- reading what came back ---------------------------------------------------------


@pytest.mark.anyio
async def test_a_credential_in_the_result_is_redacted_not_refused(
    guardrail: Guardrail, run: Run, journal: CollectingAuditSink
) -> None:
    """The call already happened; refusing the answer protects nothing."""
    decision = guardrail.permit(run, "opencode", "read", {"filePath": WORKDIR_FILE})
    reading = guardrail.inspect_result(run, decision, ["key = AKIAQYLPMN5HHHFPZAM2"])
    assert reading.decision.effect is Effect.TRANSFORM
    assert reading.texts == ("key = [redacted:aws-access-token]",)
    assert await guardrail.flush_audit() == 1
    event = journal.events()[-1]
    assert event.point is InterceptionPoint.RESPONSE
    assert event.subject == run.subject


@pytest.mark.anyio
async def test_a_result_of_many_strings_is_one_row(
    guardrail: Guardrail, run: Run, journal: CollectingAuditSink
) -> None:
    """Each string is read and cleaned on its own; the verdict is the result's."""
    decision = guardrail.permit(run, "opencode", "read", {"filePath": WORKDIR_FILE})
    texts = ["clean", "key = AKIAQYLPMN5HHHFPZAM2", "also clean"]
    reading = guardrail.inspect_result(run, decision, texts)
    assert reading.texts == ("clean", "key = [redacted:aws-access-token]", "also clean")
    assert await guardrail.flush_audit() == 1


def test_a_lost_row_does_not_become_a_leaked_secret(
    settings: Settings, policy_client: PolicyClient, journal: CollectingAuditSink
) -> None:
    """The backlog is full, so the finding cannot be recorded; the secret is cut anyway."""
    full = BufferedAuditSink(journal, GovernanceSettings(audit_backlog=0))
    guardrail = Guardrail(settings=settings, client=policy_client, audit=full, verifier=VERIFIER)
    run = guardrail.open(opening())
    decision = guardrail.permit(run, "opencode", "read", {"filePath": WORKDIR_FILE})
    reading = guardrail.inspect_result(run, decision, ["key = AKIAQYLPMN5HHHFPZAM2"])
    assert "AKIAQYLPMN5HHHFPZAM2" not in reading.texts[0]


@pytest.mark.anyio
async def test_a_clean_result_is_not_journalled(
    guardrail: Guardrail, run: Run, journal: CollectingAuditSink
) -> None:
    """A row per untouched tool result would bury the rows that mean something."""
    decision = guardrail.permit(run, "opencode", "read", {"filePath": WORKDIR_FILE})
    reading = guardrail.inspect_result(run, decision, ["def main() -> None: ..."])
    assert reading.decision.effect is Effect.ALLOW
    assert reading.texts == ("def main() -> None: ...",)
    assert await guardrail.flush_audit() == 0


def test_a_full_backlog_never_turns_a_refusal_into_a_pass(
    settings: Settings, journal: CollectingAuditSink
) -> None:
    """The record of this one is lost, but nothing was granted, which is the point."""
    full = BufferedAuditSink(journal, GovernanceSettings(audit_backlog=0))
    guardrail = Guardrail(
        settings=settings,
        client=UnconfiguredPolicyClient(GOVERNANCE.denied_message),
        audit=full,
    )
    decision = guardrail.permit(NOWHERE, "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.effect is Effect.DENY
    assert decision.enforced
    assert journal.events() == ()
