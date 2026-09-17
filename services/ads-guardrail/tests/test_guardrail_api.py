from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest
from litestar import Litestar
from litestar.testing import TestClient

from ads_guardrail.app import create_app
from ads_guardrail.config import Settings
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient
from ads_policy.contract import Binding, Capability, Effect
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy
from ads_policy.run import InMemoryRunStore
from ads_policy.service import PolicyService
from guardrail_helpers import (
    ALICE,
    ALICE_TOKEN,
    API_TOKEN,
    APPLICATION_KEY,
    BOB,
    FORGING_KEY,
    GOVERNANCE,
    PERSON_TOKEN_VERIFIER,
    WORKDIR_FILE,
    opening_body,
    person_token,
)


@pytest.fixture
def policy_service() -> PolicyService:
    retriever_bash = Binding("mcp:retriever", "bash", Capability.PROCESS_EXEC, argument="command")
    base = org_policy()
    policy = replace(base, bindings=(*base.bindings, retriever_bash))
    journal = BufferedAuditSink(CollectingAuditSink())
    return PolicyService(PolicyDecisionPoint(policy), InMemoryRunStore(), journal)


def _app(settings: Settings, policy_client: PolicyClient) -> Litestar:
    return create_app(settings, policy_client, CollectingAuditSink(), PERSON_TOKEN_VERIFIER)


@pytest.fixture
def api(settings: Settings, policy_client: PolicyClient) -> Iterator[TestClient]:
    with TestClient(app=_app(settings, policy_client)) as client:
        client.headers["authorization"] = f"Bearer {API_TOKEN}"
        yield client


@pytest.fixture
def run_id(api: TestClient) -> str:
    response = api.post("/guardrail/runs", json=opening_body())
    assert response.status_code == 201
    return str(response.json()["id"])


def _permission(
    api: TestClient,
    run_id: str,
    tool: str,
    arguments: dict[str, str] | None = None,
    source: str = "opencode",
) -> dict[str, object]:
    response = api.post(
        "/guardrail/permissions",
        json={"run_id": run_id, "source": source, "tool": tool, "arguments": arguments or {}},
    )
    assert response.status_code == 201
    return dict(response.json())


def test_each_task_gets_its_own_run(api: TestClient) -> None:
    first = api.post("/guardrail/runs", json=opening_body()).json()
    second = api.post("/guardrail/runs", json=opening_body()).json()
    assert first["subject"] == ALICE
    assert first["isolation_level"] is None
    assert first["id"] != second["id"]


def test_token_is_not_echoed(api: TestClient) -> None:
    assert ALICE_TOKEN not in api.post("/guardrail/runs", json=opening_body()).text


def test_subject_in_the_body_is_ignored(api: TestClient) -> None:
    body = {**opening_body(), "subject": BOB}
    assert api.post("/guardrail/runs", json=body).json()["subject"] == ALICE


@pytest.mark.parametrize(
    "bearer",
    [APPLICATION_KEY, person_token(key=FORGING_KEY), person_token(aud="some-other-application")],
    ids=["application-key", "forged", "other-audience"],
)
def test_run_is_not_opened_for_non_person_credentials(api: TestClient, bearer: str) -> None:
    response = api.post("/guardrail/runs", json=opening_body(bearer))
    assert response.status_code == 400
    assert bearer not in response.text


@pytest.mark.parametrize(
    "body",
    [
        None,
        {"bearer": ALICE_TOKEN},
        {"workspace": opening_body()["workspace"]},
        {"bearer": ALICE_TOKEN, "workspace": {"project": "ads"}},
    ],
)
def test_incomplete_opening_is_rejected(api: TestClient, body: dict[str, object] | None) -> None:
    assert api.post("/guardrail/runs", json=body).status_code == 400


def test_run_is_finished(api: TestClient, run_id: str) -> None:
    finished = api.post(f"/guardrail/runs/{run_id}/finish")
    assert finished.status_code == 200
    assert finished.json()["state"] == "finished"


def test_finishing_unknown_run_is_not_found(api: TestClient) -> None:
    assert api.post("/guardrail/runs/never-opened/finish").status_code == 404


def test_decision_api_requires_the_api_token(
    settings: Settings, policy_client: PolicyClient, run_id: str
) -> None:
    with TestClient(app=_app(settings, policy_client)) as anonymous:
        assert anonymous.post("/guardrail/runs", json=opening_body()).status_code == 401
        assert anonymous.post(f"/guardrail/runs/{run_id}/finish").status_code == 401
        assert anonymous.get("/health/live").status_code == 200


def test_ready_without_any_run(api: TestClient) -> None:
    assert api.get("/health/ready").status_code == 200


def test_proxy_requires_no_api_token(settings: Settings, policy_client: PolicyClient) -> None:
    with TestClient(app=_app(settings, policy_client)) as anonymous:
        response = anonymous.post("/mcp/nowhere", json={"jsonrpc": "2.0", "id": 1})
        assert response.status_code != 401


def test_permission_for_a_configured_server_uses_its_site(api: TestClient, run_id: str) -> None:
    command = {"command": "uv sync"}
    from_retriever = _permission(api, run_id, "bash", command, source="mcp:retriever")
    from_unlisted_source = _permission(api, run_id, "bash", command, source="opencode")
    assert from_retriever["effect"] == Effect.ALLOW.value
    assert from_unlisted_source["rule_id"] == "site.missing"


def test_permission_without_a_site_is_refused_for_a_run_without_level(
    api: TestClient, run_id: str
) -> None:
    decision = _permission(api, run_id, "read", {"filePath": WORKDIR_FILE})
    assert decision["effect"] == Effect.DENY.value
    assert decision["rule_id"] == "site.missing"


def test_unbound_tool_is_refused(api: TestClient, run_id: str) -> None:
    decision = _permission(api, run_id, "telepathy", {"thought": "rm -rf /"})
    assert decision["rule_id"] == "binding.missing"


def test_arguments_are_required(api: TestClient, run_id: str) -> None:
    response = api.post(
        "/guardrail/permissions",
        json={"run_id": run_id, "source": "opencode", "tool": "read"},
    )
    assert response.status_code == 400


def test_permission_without_a_run_is_unavailable(api: TestClient) -> None:
    response = api.post(
        "/guardrail/permissions",
        json={"run_id": "", "source": "opencode", "tool": "read", "arguments": {}},
    )
    assert response.status_code == 503


def test_denial_message_is_the_generic_one(api: TestClient, run_id: str) -> None:
    decision = _permission(api, run_id, "read", {"filePath": "/etc/shadow"})
    assert decision["message"] == GOVERNANCE.denied_message
    assert Capability.FS_READ.value not in str(decision["message"])
