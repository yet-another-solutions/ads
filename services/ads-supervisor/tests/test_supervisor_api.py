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
from supervisor_helpers import TOKEN

GOVERNANCE = GovernanceSettings()


@pytest.fixture
def api(settings: Settings, policy_client: PolicyClient) -> Iterator[TestClient]:
    with TestClient(app=create_app(settings, policy_client, CollectingAuditSink())) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        yield client


def _permit(api: TestClient, capability: Capability, resource: str) -> dict[str, object]:
    response = api.post(
        "/supervisor/permissions",
        json={"capability": capability.value, "resource": resource},
    )
    assert response.status_code == 201
    return dict(response.json())


def test_the_run_opens_with_the_process(api: TestClient) -> None:
    run = api.get("/supervisor/run").json()
    assert run["subject"] == "alice"
    assert run["isolation_level"] == IsolationLevel.VM.value
    assert api.get("/health/ready").status_code == 200


def test_the_api_needs_the_token(settings: Settings, policy_client: PolicyClient) -> None:
    app = create_app(settings, policy_client, CollectingAuditSink())
    with TestClient(app=app) as client:
        assert client.get("/supervisor/run").status_code == 401
        assert client.get("/health/live").status_code == 200


def test_a_permission_request_is_answered(api: TestClient) -> None:
    allowed = _permit(api, Capability.FS_READ, f"{GOVERNANCE.workdir}/src/app.py")
    assert allowed["effect"] == Effect.ALLOW.value
    denied = _permit(api, Capability.SECRET_READ, "ads-client-secret")
    assert denied["effect"] == Effect.DENY.value
    assert denied["message"] == GOVERNANCE.denied_message


def test_an_unknown_capability_is_refused(api: TestClient) -> None:
    """The vocabulary is closed: opencode tool names do not reach the policy service."""
    response = api.post(
        "/supervisor/permissions",
        json={"capability": "bash", "resource": "uv sync"},
    )
    assert response.status_code == 400
