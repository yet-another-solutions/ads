from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from ads_guardrail.config import Settings
from ads_guardrail.contract import Application, Sandbox
from ads_guardrail.guardrail import (
    Guardrail,
    NotAPerson,
    RunNotOpen,
    application_key,
    fingerprint,
)
from ads_policy.audit import BufferedAuditSink
from ads_policy.client import PolicyClient
from ads_policy.contract import Effect, IsolationLevel, Placement, RunRequest, RunState
from guardrail_helpers import ALICE, APP_KEY, GOVERNANCE, USER_TOKEN, VERIFIER, opening

WORKDIR_FILE = f"{GOVERNANCE.workdir}/src/app.py"

#: Where hermes runs, as whoever deployed it says: an ordinary pod on an application node.
APPLICATION_NODE = Sandbox(
    project="ads",
    repo="yet-another-solutions/ads",
    env="test",
    workdir=GOVERNANCE.workdir,
    placement=Placement.CLUSTER,
    node_labels={GOVERNANCE.application_node_label: GOVERNANCE.node_label_value},
)
HERMES = Application(name="hermes", key_sha256=fingerprint(APP_KEY), sandbox=APPLICATION_NODE)


@pytest.fixture
def configured(settings: Settings) -> Settings:
    return replace(settings, applications=(HERMES,))


@pytest.fixture
def guardrail(
    configured: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> Guardrail:
    return Guardrail(settings=configured, client=policy_client, audit=audit, verifier=VERIFIER)


def test_the_first_call_opens_the_application_s_run(guardrail: Guardrail) -> None:
    """Nothing in hermes's path knows the guardrail is there, so nobody else would."""
    run = guardrail.find(APP_KEY)
    assert run.subject == "hermes"
    assert run.state is RunState.RUNNING
    assert run.holder == application_key(HERMES.key_sha256)


def test_the_key_itself_is_not_kept(guardrail: Guardrail) -> None:
    assert APP_KEY not in guardrail.find(APP_KEY).holder


def test_the_run_follows_where_the_application_was_deployed(guardrail: Guardrail) -> None:
    assert guardrail.find(APP_KEY).isolation_level is IsolationLevel.CONTAINER


def test_later_calls_stay_in_the_same_run(guardrail: Guardrail) -> None:
    first = guardrail.find(APP_KEY)
    assert guardrail.find(APP_KEY).id == first.id


def test_a_finished_run_is_replaced(guardrail: Guardrail) -> None:
    """The lifetime ran out, or someone closed it: the next call carries on in a new one."""
    first = guardrail.find(APP_KEY)
    guardrail.finish(first.id)
    second = guardrail.find(APP_KEY)
    assert second.id != first.id
    assert second.state is RunState.RUNNING


def test_a_revoked_run_is_not_replaced(guardrail: Guardrail, policy_client: PolicyClient) -> None:
    """Otherwise revoking an application would mean nothing."""
    first = guardrail.find(APP_KEY)
    policy_client.revoke_run(first.id)
    again = guardrail.find(APP_KEY)
    assert again.id == first.id
    decision = guardrail.permit(again, "opencode", "read", {"filePath": WORKDIR_FILE})
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "run.state"


def test_calls_arriving_together_open_one_run(guardrail: Guardrail) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        runs = list(pool.map(lambda _: guardrail.find(APP_KEY), range(16)))
    assert len({run.id for run in runs}) == 1


def test_two_replicas_opening_at_once_do_not_stop_the_application(
    guardrail: Guardrail, configured: Settings, policy_client: PolicyClient
) -> None:
    """Each may open one; either will do, and both replicas settle on the same."""
    other = Guardrail(settings=configured, client=policy_client, audit=guardrail.audit)
    opened = [
        policy_client.start_run(
            RunRequest(
                subject="hermes",
                project=APPLICATION_NODE.project,
                repo=APPLICATION_NODE.repo,
                env=APPLICATION_NODE.env,
                workdir=APPLICATION_NODE.workdir,
                node_labels=dict(APPLICATION_NODE.node_labels),
                holder=application_key(HERMES.key_sha256),
            )
        )
        for _ in range(2)
    ]
    chosen = guardrail.find(APP_KEY)
    assert chosen.id == min(run.id for run in opened)
    assert other.find(APP_KEY).id == chosen.id


def test_an_application_needs_no_verifier(
    configured: Settings, policy_client: PolicyClient, audit: BufferedAuditSink
) -> None:
    """Its key is recognised by fingerprint; there is no token of a person to check."""
    keyed = Guardrail(
        settings=replace(configured, mcp_audience=""), client=policy_client, audit=audit
    )
    assert keyed.find(APP_KEY).subject == "hermes"


def test_an_application_s_run_is_not_opened_by_a_launcher(guardrail: Guardrail) -> None:
    """Its key is not a person's token, and its runs are opened here."""
    with pytest.raises(NotAPerson):
        guardrail.open(opening(APPLICATION_NODE, bearer=APP_KEY))


def test_a_person_is_not_an_application(guardrail: Guardrail) -> None:
    """Only a configured key has a run opened for it; a person needs a launcher."""
    with pytest.raises(RunNotOpen):
        guardrail.find(USER_TOKEN)
    guardrail.open(opening())
    assert guardrail.find(USER_TOKEN).subject == ALICE


def test_an_application_run_cannot_be_named_by_someone_else(guardrail: Guardrail) -> None:
    theirs = guardrail.find(APP_KEY)
    guardrail.open(opening())
    with pytest.raises(RunNotOpen):
        guardrail.find(USER_TOKEN, theirs.id)
