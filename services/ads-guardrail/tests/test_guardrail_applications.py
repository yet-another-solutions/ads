from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from ads_guardrail.config import Settings
from ads_guardrail.contract import Application
from ads_guardrail.guardrail import (
    Guardrail,
    NotAPerson,
    RunNotOpen,
    application_holder_key,
    fingerprint,
)
from ads_policy.audit import BufferedAuditSink
from ads_policy.client import PolicyClient
from ads_policy.contract import Effect, RunRequest, RunState
from guardrail_helpers import (
    ALICE,
    ALICE_TOKEN,
    APPLICATION_KEY,
    KATA_VM_SITE,
    PERSON_TOKEN_VERIFIER,
    WORKDIR_FILE,
    WORKSPACE,
    opening,
)

HERMES = Application(name="hermes", key_sha256=fingerprint(APPLICATION_KEY), workspace=WORKSPACE)
HERMES_HOLDER = application_holder_key(HERMES.key_sha256)


@pytest.fixture
def with_hermes(settings: Settings) -> Settings:
    return replace(settings, applications=(HERMES,))


@pytest.fixture
def guardrail(
    with_hermes: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> Guardrail:
    return Guardrail(
        settings=with_hermes,
        client=policy_client,
        audit=audit,
        person_token_verifier=PERSON_TOKEN_VERIFIER,
    )


def test_first_call_opens_the_application_run(guardrail: Guardrail) -> None:
    run = guardrail.find_run_of_caller(APPLICATION_KEY)
    assert run.subject == "hermes"
    assert run.state is RunState.RUNNING
    assert run.holder == HERMES_HOLDER


def test_application_key_is_not_stored(guardrail: Guardrail) -> None:
    assert APPLICATION_KEY not in guardrail.find_run_of_caller(APPLICATION_KEY).holder


def test_later_calls_stay_in_the_same_run(guardrail: Guardrail) -> None:
    first = guardrail.find_run_of_caller(APPLICATION_KEY)
    assert guardrail.find_run_of_caller(APPLICATION_KEY).id == first.id


def test_finished_run_is_replaced(guardrail: Guardrail) -> None:
    first = guardrail.find_run_of_caller(APPLICATION_KEY)
    guardrail.finish_run(first.id)
    second = guardrail.find_run_of_caller(APPLICATION_KEY)
    assert second.id != first.id
    assert second.state is RunState.RUNNING


def test_revoked_run_is_not_replaced(guardrail: Guardrail, policy_client: PolicyClient) -> None:
    first = guardrail.find_run_of_caller(APPLICATION_KEY)
    policy_client.revoke_run(first.id)
    again = guardrail.find_run_of_caller(APPLICATION_KEY)
    assert again.id == first.id
    decision = guardrail.decide_tool_call(
        again, "opencode", "read", {"filePath": WORKDIR_FILE}, site=KATA_VM_SITE
    )
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "run.state"


def test_concurrent_first_calls_open_one_run(guardrail: Guardrail) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        runs = list(pool.map(lambda _: guardrail.find_run_of_caller(APPLICATION_KEY), range(16)))
    assert len({run.id for run in runs}) == 1


def test_replicas_settle_on_the_same_run_when_two_were_opened(
    guardrail: Guardrail, with_hermes: Settings, policy_client: PolicyClient
) -> None:
    other_replica = Guardrail(settings=with_hermes, client=policy_client, audit=guardrail.audit)
    opened = [
        policy_client.start_run(
            RunRequest(
                subject="hermes",
                project=WORKSPACE.project,
                repo=WORKSPACE.repo,
                env=WORKSPACE.env,
                workdir=WORKSPACE.workdir,
                placement=None,
                holder=HERMES_HOLDER,
            )
        )
        for _ in range(2)
    ]
    chosen = guardrail.find_run_of_caller(APPLICATION_KEY)
    assert chosen.id == min(run.id for run in opened)
    assert other_replica.find_run_of_caller(APPLICATION_KEY).id == chosen.id


def test_application_works_without_person_token_verification(
    with_hermes: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> None:
    guardrail = Guardrail(
        settings=replace(with_hermes, person_token_audience=""),
        client=policy_client,
        audit=audit,
    )
    assert guardrail.find_run_of_caller(APPLICATION_KEY).subject == "hermes"


def test_launcher_cannot_open_a_run_with_an_application_key(guardrail: Guardrail) -> None:
    with pytest.raises(NotAPerson):
        guardrail.open_run(opening(APPLICATION_KEY))


def test_person_needs_a_launched_run(guardrail: Guardrail) -> None:
    with pytest.raises(RunNotOpen):
        guardrail.find_run_of_caller(ALICE_TOKEN)
    guardrail.open_run(opening())
    assert guardrail.find_run_of_caller(ALICE_TOKEN).subject == ALICE


def test_person_cannot_name_the_application_run(guardrail: Guardrail) -> None:
    hermes_run = guardrail.find_run_of_caller(APPLICATION_KEY)
    guardrail.open_run(opening())
    with pytest.raises(RunNotOpen):
        guardrail.find_run_of_caller(ALICE_TOKEN, hermes_run.id)
