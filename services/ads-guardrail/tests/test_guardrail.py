from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

import msgspec
import pytest

from ads_guardrail.config import Settings
from ads_guardrail.guardrail import Guardrail, NotAPerson, RunNotOpen, person_holder_key
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient, UnconfiguredPolicyClient
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    Effect,
    InterceptionPoint,
    IsolationLevel,
    PolicyDecision,
    Run,
    RunContext,
    Site,
)
from guardrail_helpers import (
    ALICE,
    ALICE_TOKEN,
    APPLICATION_NODE_SITE,
    BOB,
    FORGING_KEY,
    GOVERNANCE,
    KATA_ON_UNLABELLED_NODE_SITE,
    KATA_VM_SITE,
    PERSON_TOKEN_VERIFIER,
    WORKDIR_FILE,
    WORKSTATION_SITE,
    UnreachablePolicyClient,
    opening,
    person_token,
)

AWS_KEY = "AKIAQYLPMN5HHHFPZAM2"
RUN_NEVER_OPENED = Run(
    id="run-1",
    subject=ALICE,
    context=RunContext(project="ads", repo="ads", env="dev", workdir=GOVERNANCE.workdir),
    isolation_level=None,
    policy_hash="",
)


def _decide(
    guardrail: Guardrail,
    run: Run,
    tool: str,
    arguments: Mapping[str, str],
    site: Site | None = KATA_VM_SITE,
) -> PolicyDecision:
    return guardrail.decide_tool_call(run, "opencode", tool, arguments, site=site)


def test_run_belongs_to_the_person_the_token_names(guardrail: Guardrail) -> None:
    run = guardrail.open_run(opening(person_token(BOB)))
    assert run.subject == BOB
    assert run.holder == person_holder_key(BOB)


def test_run_has_no_level_of_its_own(alice_run: Run) -> None:
    assert alice_run.isolation_level is None


def test_token_is_not_stored_on_the_run(alice_run: Run) -> None:
    assert ALICE_TOKEN not in msgspec.json.encode(alice_run).decode()


@pytest.mark.parametrize(
    "bearer",
    [
        "not-a-jwt",
        "",
        person_token(key=FORGING_KEY),
        person_token(aud="some-other-application"),
        person_token(iss="https://elsewhere.test/realms/ads"),
        person_token(issued_seconds_from_now=-3600),
        person_token(sub="alice"),
    ],
    ids=["garbage", "empty", "forged", "other-audience", "other-issuer", "expired", "not-uuid"],
)
def test_run_is_not_opened_on_unverified_token(guardrail: Guardrail, bearer: str) -> None:
    with pytest.raises(NotAPerson, match="does not verify"):
        guardrail.open_run(opening(bearer))


def test_without_audience_no_person_is_recognised(
    settings: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> None:
    guardrail = Guardrail(
        settings=replace(settings, person_token_audience=""),
        client=policy_client,
        audit=audit,
        person_token_verifier=PERSON_TOKEN_VERIFIER,
    )
    with pytest.raises(NotAPerson, match="no audience"):
        guardrail.open_run(opening())


def test_without_verifier_no_person_is_recognised(
    settings: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> None:
    guardrail = Guardrail(settings=settings, client=policy_client, audit=audit)
    with pytest.raises(NotAPerson):
        guardrail.open_run(opening())


def test_unreachable_policy_service_opens_no_run(
    settings: Settings, audit: BufferedAuditSink
) -> None:
    guardrail = Guardrail(
        settings=settings,
        client=UnreachablePolicyClient(),
        audit=audit,
        person_token_verifier=PERSON_TOKEN_VERIFIER,
    )
    with pytest.raises(ConnectionError):
        guardrail.open_run(opening())


def test_call_finds_the_run_of_its_person(guardrail: Guardrail, alice_run: Run) -> None:
    assert guardrail.find_run_of_caller(ALICE_TOKEN).id == alice_run.id


def test_refreshed_token_stays_in_the_same_run(guardrail: Guardrail, alice_run: Run) -> None:
    refreshed = person_token(ALICE, issued_seconds_from_now=-60, jti="refreshed")
    assert guardrail.find_run_of_caller(refreshed).id == alice_run.id


def test_expired_token_finds_nothing(guardrail: Guardrail, alice_run: Run) -> None:
    with pytest.raises(RunNotOpen, match="does not verify"):
        guardrail.find_run_of_caller(person_token(ALICE, issued_seconds_from_now=-3600))


def test_forged_token_finds_nothing(guardrail: Guardrail, alice_run: Run) -> None:
    with pytest.raises(RunNotOpen, match="does not verify"):
        guardrail.find_run_of_caller(person_token(ALICE, key=FORGING_KEY))


def test_call_without_credentials_finds_nothing(guardrail: Guardrail, alice_run: Run) -> None:
    with pytest.raises(RunNotOpen):
        guardrail.find_run_of_caller("")


def test_person_without_a_run_finds_nothing(guardrail: Guardrail, alice_run: Run) -> None:
    with pytest.raises(RunNotOpen, match="no run is open"):
        guardrail.find_run_of_caller(person_token(BOB))


def test_two_runs_of_one_person_must_be_named(guardrail: Guardrail) -> None:
    first = guardrail.open_run(opening())
    second = guardrail.open_run(opening())
    with pytest.raises(RunNotOpen, match="name one"):
        guardrail.find_run_of_caller(ALICE_TOKEN)
    assert guardrail.find_run_of_caller(ALICE_TOKEN, second.id).id == second.id
    assert guardrail.find_run_of_caller(ALICE_TOKEN, first.id).id == first.id


def test_named_run_must_belong_to_the_caller(guardrail: Guardrail, alice_run: Run) -> None:
    bobs = guardrail.open_run(opening(person_token(BOB)))
    with pytest.raises(RunNotOpen, match="not its own"):
        guardrail.find_run_of_caller(ALICE_TOKEN, bobs.id)


def test_revoked_run_is_still_found_so_its_refusal_is_journalled(
    guardrail: Guardrail, alice_run: Run, policy_client: PolicyClient
) -> None:
    policy_client.revoke_run(alice_run.id)
    found = guardrail.find_run_of_caller(ALICE_TOKEN)
    assert found.id == alice_run.id
    assert _decide(guardrail, found, "read", {"filePath": WORKDIR_FILE}).rule_id == "run.state"


def test_next_task_is_found_once_the_last_is_finished(guardrail: Guardrail) -> None:
    first = guardrail.open_run(opening())
    guardrail.finish_run(first.id)
    second = guardrail.open_run(opening())
    assert guardrail.find_run_of_caller(ALICE_TOKEN).id == second.id


def test_finishing_unknown_run_returns_nothing(guardrail: Guardrail) -> None:
    assert guardrail.finish_run("never-opened") is None


def test_finishing_needs_the_policy_service(settings: Settings, audit: BufferedAuditSink) -> None:
    guardrail = Guardrail(settings=settings, client=UnreachablePolicyClient(), audit=audit)
    with pytest.raises(RunNotOpen):
        guardrail.finish_run("run-1")


def test_unreachable_policy_service_finds_nothing(
    settings: Settings, audit: BufferedAuditSink
) -> None:
    guardrail = Guardrail(
        settings=settings,
        client=UnreachablePolicyClient(),
        audit=audit,
        person_token_verifier=PERSON_TOKEN_VERIFIER,
    )
    with pytest.raises(RunNotOpen, match="cannot be looked up"):
        guardrail.find_run_of_caller(ALICE_TOKEN)


def test_get_run_by_id(guardrail: Guardrail, alice_run: Run) -> None:
    assert guardrail.get_run(alice_run.id).id == alice_run.id
    with pytest.raises(RunNotOpen):
        guardrail.get_run("")
    with pytest.raises(RunNotOpen):
        guardrail.get_run("never-opened")


def test_level_comes_from_the_site_of_the_called_server(
    guardrail: Guardrail, alice_run: Run
) -> None:
    command = {"command": "uv sync"}
    assert _decide(guardrail, alice_run, "bash", command, KATA_VM_SITE).effect is Effect.ALLOW
    in_container = _decide(guardrail, alice_run, "bash", command, APPLICATION_NODE_SITE)
    assert in_container.effect is Effect.DENY


def test_internet_is_reachable_only_from_a_workstation_site(
    guardrail: Guardrail, alice_run: Run
) -> None:
    fetch = {"url": "https://example.com/"}
    assert _decide(guardrail, alice_run, "webfetch", fetch, WORKSTATION_SITE).permitted
    assert not _decide(guardrail, alice_run, "webfetch", fetch, KATA_VM_SITE).permitted


def test_call_without_site_in_a_run_without_level_is_refused(
    guardrail: Guardrail, alice_run: Run
) -> None:
    decision = _decide(guardrail, alice_run, "read", {"filePath": WORKDIR_FILE}, site=None)
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "site.missing"


def test_kata_site_on_unlabelled_node_is_refused(guardrail: Guardrail, alice_run: Run) -> None:
    decision = _decide(
        guardrail, alice_run, "read", {"filePath": WORKDIR_FILE}, KATA_ON_UNLABELLED_NODE_SITE
    )
    assert decision.rule_id == "site.unknown"


def test_one_process_serves_many_runs(guardrail: Guardrail) -> None:
    alice = guardrail.open_run(opening())
    bob = guardrail.open_run(opening(person_token(BOB)))
    for run in (alice, bob):
        assert _decide(guardrail, run, "read", {"filePath": WORKDIR_FILE}).effect is Effect.ALLOW


def test_denial_message_reveals_nothing(guardrail: Guardrail, alice_run: Run) -> None:
    decision = _decide(guardrail, alice_run, "read", {"filePath": "/etc/shadow"})
    assert decision.effect is Effect.DENY
    assert decision.message == GOVERNANCE.denied_message
    assert Capability.FS_READ.value not in decision.message
    for level in IsolationLevel:
        assert level.value not in decision.message


def test_commands_are_not_inspected_by_the_guardrail(guardrail: Guardrail, alice_run: Run) -> None:
    for command in ("rm -rf /workspace", "uv sync"):
        assert _decide(guardrail, alice_run, "bash", {"command": command}).permitted


def test_unbound_tool_is_refused(guardrail: Guardrail, alice_run: Run) -> None:
    decision = _decide(guardrail, alice_run, "telepathy", {"thought": "rm -rf /"})
    assert decision.rule_id == "binding.missing"


def test_call_missing_its_resource_argument_is_refused(
    guardrail: Guardrail, alice_run: Run
) -> None:
    decision = _decide(guardrail, alice_run, "read", {"somethingElse": "/x"})
    assert decision.rule_id == "binding.resource"


def test_decision_names_the_recognised_capability(guardrail: Guardrail, alice_run: Run) -> None:
    decision = _decide(guardrail, alice_run, "read", {"filePath": WORKDIR_FILE})
    assert decision.capability is Capability.FS_READ
    assert decision.resource == WORKDIR_FILE


@pytest.mark.anyio
async def test_policy_service_decisions_are_not_journalled_twice(
    guardrail: Guardrail, alice_run: Run, journal: CollectingAuditSink
) -> None:
    _decide(guardrail, alice_run, "read", {"filePath": WORKDIR_FILE})
    _decide(guardrail, alice_run, "read", {"filePath": "/etc/shadow"})
    assert await guardrail.flush_audit() == 0
    assert journal.events() == ()


@pytest.mark.anyio
async def test_decision_made_without_the_policy_service_is_journalled_here(
    settings: Settings, audit: BufferedAuditSink, journal: CollectingAuditSink
) -> None:
    guardrail = Guardrail(
        settings=settings,
        client=UnconfiguredPolicyClient(GOVERNANCE.denied_message),
        audit=audit,
    )
    decision = _decide(guardrail, RUN_NEVER_OPENED, "read", {"filePath": WORKDIR_FILE})
    assert decision.rule_id == "policy.unreachable"
    assert await guardrail.flush_audit() == 1
    assert journal.events()[-1].rule_id == "policy.unreachable"
    assert journal.events()[-1].subject == ALICE


def test_credential_in_arguments_turns_permission_into_refusal(
    guardrail: Guardrail, alice_run: Run
) -> None:
    decision = _decide(
        guardrail, alice_run, "webfetch", {"url": "mirror.interlab", "body": f"KEY={AWS_KEY}"}
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "payload.leak"
    assert decision.point is InterceptionPoint.REQUEST
    assert decision.weight == GOVERNANCE.leak_weight
    assert decision.message == GOVERNANCE.denied_message


def test_clean_arguments_keep_the_permission(guardrail: Guardrail, alice_run: Run) -> None:
    decision = _decide(
        guardrail, alice_run, "webfetch", {"url": "mirror.interlab", "body": "GET /simple"}
    )
    assert decision.effect is Effect.ALLOW
    assert decision.point is InterceptionPoint.CALL


def test_refused_call_is_not_inspected(guardrail: Guardrail, alice_run: Run) -> None:
    decision = _decide(guardrail, alice_run, "read", {"filePath": "/etc/shadow", "body": AWS_KEY})
    assert decision.rule_id == "fs.read.outside"
    assert decision.point is InterceptionPoint.CALL


@pytest.mark.anyio
async def test_leak_is_journalled_as_the_recognised_capability(
    guardrail: Guardrail, alice_run: Run, journal: CollectingAuditSink
) -> None:
    _decide(guardrail, alice_run, "webfetch", {"url": "mirror.interlab", "body": AWS_KEY})
    assert await guardrail.flush_audit() == 1
    event = journal.events()[-1]
    assert event.rule_id == "payload.leak"
    assert event.point is InterceptionPoint.REQUEST
    assert event.capability is Capability.NET_EGRESS
    assert event.subject == ALICE


@pytest.mark.anyio
async def test_credential_in_result_is_redacted(
    guardrail: Guardrail, alice_run: Run, journal: CollectingAuditSink
) -> None:
    decision = _decide(guardrail, alice_run, "read", {"filePath": WORKDIR_FILE})
    reading = guardrail.inspect_tool_result(alice_run, decision, [f"key = {AWS_KEY}"])
    assert reading.decision.effect is Effect.TRANSFORM
    assert reading.texts == ("key = [redacted:aws-access-token]",)
    assert await guardrail.flush_audit() == 1
    assert journal.events()[-1].point is InterceptionPoint.RESPONSE


@pytest.mark.anyio
async def test_result_of_many_strings_is_one_journal_row(
    guardrail: Guardrail, alice_run: Run
) -> None:
    decision = _decide(guardrail, alice_run, "read", {"filePath": WORKDIR_FILE})
    texts = ["clean", f"key = {AWS_KEY}", "also clean"]
    reading = guardrail.inspect_tool_result(alice_run, decision, texts)
    assert reading.texts == ("clean", "key = [redacted:aws-access-token]", "also clean")
    assert await guardrail.flush_audit() == 1


def test_redaction_survives_a_full_journal(
    settings: Settings, policy_client: PolicyClient, journal: CollectingAuditSink
) -> None:
    guardrail = Guardrail(
        settings=settings,
        client=policy_client,
        audit=BufferedAuditSink(journal, GovernanceSettings(audit_backlog=0)),
        person_token_verifier=PERSON_TOKEN_VERIFIER,
    )
    run = guardrail.open_run(opening())
    decision = _decide(guardrail, run, "read", {"filePath": WORKDIR_FILE})
    reading = guardrail.inspect_tool_result(run, decision, [f"key = {AWS_KEY}"])
    assert AWS_KEY not in reading.texts[0]


@pytest.mark.anyio
async def test_clean_result_is_not_journalled(guardrail: Guardrail, alice_run: Run) -> None:
    decision = _decide(guardrail, alice_run, "read", {"filePath": WORKDIR_FILE})
    reading = guardrail.inspect_tool_result(alice_run, decision, ["def main() -> None: ..."])
    assert reading.decision.effect is Effect.ALLOW
    assert reading.texts == ("def main() -> None: ...",)
    assert await guardrail.flush_audit() == 0


def test_full_journal_never_turns_refusal_into_permission(
    settings: Settings, journal: CollectingAuditSink
) -> None:
    guardrail = Guardrail(
        settings=settings,
        client=UnconfiguredPolicyClient(GOVERNANCE.denied_message),
        audit=BufferedAuditSink(journal, GovernanceSettings(audit_backlog=0)),
    )
    decision = _decide(guardrail, RUN_NEVER_OPENED, "read", {"filePath": WORKDIR_FILE})
    assert decision.effect is Effect.DENY
    assert decision.enforced
    assert journal.events() == ()
