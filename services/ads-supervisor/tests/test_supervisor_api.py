from __future__ import annotations

from collections.abc import Iterator

import pytest
from litestar.testing import TestClient

from ads_policy.audit import CollectingAuditSink
from ads_policy.client import PolicyClient
from ads_policy.config import GovernanceSettings
from ads_policy.contract import Capability, Effect, IsolationLevel
from ads_supervisor.app import create_app
from ads_supervisor.config import Settings
from supervisor_helpers import TOKEN, WORKSTATION, sandbox_body

GOVERNANCE = GovernanceSettings()


@pytest.fixture
def api(settings: Settings, policy_client: PolicyClient) -> Iterator[TestClient]:
    with TestClient(app=create_app(settings, policy_client, CollectingAuditSink())) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        yield client


@pytest.fixture
def run(api: TestClient) -> str:
    response = api.post("/supervisor/runs", json=sandbox_body())
    assert response.status_code == 201
    return str(response.json()["id"])


def _permit(
    api: TestClient,
    run: str,
    tool: str,
    arguments: dict[str, str] | None = None,
    source: str = "opencode",
) -> dict[str, object]:
    response = api.post(
        "/supervisor/permissions",
        json={"run_id": run, "source": source, "tool": tool, "arguments": arguments or {}},
    )
    assert response.status_code == 201
    return dict(response.json())


def test_a_run_is_opened_per_task(api: TestClient) -> None:
    """The launcher opens one of these for each task it puts in a sandbox."""
    first = api.post("/supervisor/runs", json=sandbox_body()).json()
    second = api.post("/supervisor/runs", json=sandbox_body()).json()
    assert first["subject"] == "alice"
    assert first["isolation_level"] == IsolationLevel.VM.value
    assert first["id"] != second["id"]


def test_the_level_follows_the_sandbox_the_launcher_describes(api: TestClient) -> None:
    opened = api.post("/supervisor/runs", json=sandbox_body(WORKSTATION)).json()
    assert opened["isolation_level"] == IsolationLevel.LOCAL.value


def test_a_run_cannot_be_opened_without_saying_where(api: TestClient) -> None:
    """A guessed placement would decide under the wrong rules."""
    assert api.post("/supervisor/runs").status_code == 400
    assert api.post("/supervisor/runs", json={"project": "ads"}).status_code == 400


def test_the_process_is_ready_without_a_run(api: TestClient) -> None:
    """It holds none of its own: readiness cannot depend on one existing."""
    assert api.get("/health/ready").status_code == 200


def test_the_decision_api_needs_the_token(settings: Settings, policy_client: PolicyClient) -> None:
    app = create_app(settings, policy_client, CollectingAuditSink())
    with TestClient(app=app) as client:
        assert client.post("/supervisor/runs", json=sandbox_body()).status_code == 401
        assert client.get("/health/live").status_code == 200


def test_the_proxy_needs_no_token(settings: Settings, policy_client: PolicyClient) -> None:
    """The agent is not made to authenticate to something it does not know is there."""
    app = create_app(settings, policy_client, CollectingAuditSink())
    with TestClient(app=app) as client:
        assert client.post("/mcp/nowhere", json={"jsonrpc": "2.0", "id": 1}).status_code != 401


def test_a_permission_request_is_answered(api: TestClient, run: str) -> None:
    allowed = _permit(api, run, "read", {"filePath": f"{GOVERNANCE.workdir}/src/app.py"})
    assert allowed["effect"] == Effect.ALLOW.value
    assert allowed["capability"] == Capability.FS_READ.value
    denied = _permit(api, run, "read", {"filePath": "/etc/shadow"})
    assert denied["effect"] == Effect.DENY.value
    assert denied["message"] == GOVERNANCE.denied_message


def test_a_tool_nothing_binds_is_refused(api: TestClient, run: str) -> None:
    """The vocabulary stays closed: an unrecognised tool resolves to nothing."""
    denied = _permit(api, run, "telepathy", {"thought": "rm -rf /"})
    assert denied["effect"] == Effect.DENY.value
    assert denied["rule_id"] == "binding.missing"


def test_a_tool_from_an_unknown_source_is_refused(api: TestClient, run: str) -> None:
    denied = _permit(api, run, "read", {"filePath": "/workspace/app.py"}, source="mcp:jira")
    assert denied["effect"] == Effect.DENY.value
    assert denied["rule_id"] == "binding.missing"


def test_arguments_are_required(api: TestClient, run: str) -> None:
    """Otherwise "nothing to check" and "never checked" arrive as the same request."""
    response = api.post(
        "/supervisor/permissions",
        json={"run_id": run, "source": "opencode", "tool": "read"},
    )
    assert response.status_code == 400


def test_a_call_without_a_run_is_refused(api: TestClient) -> None:
    response = api.post(
        "/supervisor/permissions",
        json={"run_id": "", "source": "opencode", "tool": "read", "arguments": {}},
    )
    assert response.status_code == 503


def test_a_credential_in_the_arguments_is_refused_over_http(api: TestClient, run: str) -> None:
    denied = _permit(
        api,
        run,
        "webfetch",
        {"url": "mirror.interlab", "body": "AWS_KEY=AKIAQYLPMN5HHHFPZAM2"},
    )
    assert denied["effect"] == Effect.DENY.value
    assert denied["rule_id"] == "payload.leak"
    assert denied["message"] == GOVERNANCE.denied_message
