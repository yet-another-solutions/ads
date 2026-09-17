from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import fakeredis
import pytest
from litestar.testing import TestClient
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from ads_policy.app import create_app
from ads_policy.audit import CollectingAuditSink
from ads_policy.config import GovernanceSettings, Settings
from ads_policy.contract import Capability, Effect, IsolationLevel

TOKEN = "policy-api-token-32-bytes-long"
SETTINGS = GovernanceSettings()


class _UnreachableRedis(fakeredis.FakeAsyncRedis):  # type: ignore[misc]
    async def ping(self, *args: object, **kwargs: object) -> bool:
        raise RedisConnectionError("no route to the run store")


@pytest.fixture
def service_settings(tmp_path: Path) -> Settings:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    return Settings(
        api_token=TOKEN,
        tls_cert_path=cert,
        tls_key_path=key,
        redis_url="redis://unused",
        amqp_url="amqp://unused",
        governance=GovernanceSettings(policy_dir=tmp_path / "missing"),
    )


@pytest.fixture
def api(service_settings: Settings, redis: Redis) -> Iterator[TestClient]:
    with TestClient(app=create_app(service_settings, redis, CollectingAuditSink())) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        yield client


def _start(api: TestClient, *, subject: str = "alice", vm: bool = True) -> dict[str, object]:
    body = {
        "subject": subject,
        "project": "ads",
        "repo": "yet-another-solutions/ads",
        "env": "dev",
        "workdir": SETTINGS.workdir,
        "runtime_class_name": SETTINGS.vm_runtime_class if vm else None,
        "node_labels": (
            {
                SETTINGS.sandbox_node_label: SETTINGS.node_label_value,
                SETTINGS.application_node_label: SETTINGS.node_label_value,
            }
            if vm
            else {SETTINGS.application_node_label: SETTINGS.node_label_value}
        ),
    }
    response = api.post("/policy/runs", json=body)
    assert response.status_code == 201
    return dict(response.json())


def test_health_is_public(service_settings: Settings, redis: Redis) -> None:
    with TestClient(app=create_app(service_settings, redis, CollectingAuditSink())) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").json() == {"status": "ok"}


def test_readiness_follows_the_run_store(service_settings: Settings) -> None:
    app = create_app(service_settings, _UnreachableRedis(), CollectingAuditSink())
    with TestClient(app=app) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 503


def test_the_api_needs_the_token(service_settings: Settings, redis: Redis) -> None:
    with TestClient(app=create_app(service_settings, redis, CollectingAuditSink())) as client:
        assert client.get("/policy/version").status_code == 401
        client.headers["authorization"] = "Bearer wrong-token-wrong-token"
        assert client.get("/policy/version").status_code == 401
        client.headers["authorization"] = f"Bearer {TOKEN}"
        assert client.get("/policy/version").status_code == 200


def test_the_version_is_the_hash_the_pdp_computed(api: TestClient) -> None:
    payload = api.get("/policy/version").json()
    assert payload["version"] == SETTINGS.policy_version
    assert len(payload["hash"]) == 64
    assert payload["mode"] == SETTINGS.mode.value


def test_the_service_derives_the_level_from_the_placement(api: TestClient) -> None:
    assert _start(api, vm=True)["isolation_level"] == IsolationLevel.VM.value
    assert _start(api, vm=False)["isolation_level"] == IsolationLevel.CONTAINER.value


def test_an_unconfirmed_placement_opens_no_run(api: TestClient) -> None:
    response = api.post(
        "/policy/runs",
        json={
            "subject": "alice",
            "project": "ads",
            "repo": "yet-another-solutions/ads",
            "env": "dev",
            "workdir": SETTINGS.workdir,
        },
    )
    assert response.status_code == 400
    assert "placement not confirmed" in response.text


def test_a_workstation_states_its_own_placement(api: TestClient) -> None:
    response = api.post(
        "/policy/runs",
        json={
            "subject": "alice",
            "project": "ads",
            "repo": "yet-another-solutions/ads",
            "env": "dev",
            "workdir": SETTINGS.workdir,
            "placement": "workstation",
        },
    )
    assert response.status_code == 201
    assert response.json()["isolation_level"] == IsolationLevel.LOCAL.value


def test_the_run_pins_the_policy_version(api: TestClient) -> None:
    run = _start(api)
    assert run["policy_hash"] == api.get("/policy/version").json()["hash"]


def test_a_decision_comes_back_over_the_api(api: TestClient) -> None:
    run = _start(api)
    allowed = api.post(
        "/policy/decide",
        json={
            "run_id": run["id"],
            "subject": "alice",
            "capability": Capability.FS_READ.value,
            "resource": f"{SETTINGS.workdir}/src/app.py",
        },
    )
    assert allowed.status_code == 201
    assert allowed.json()["effect"] == Effect.ALLOW.value
    denied = api.post(
        "/policy/decide",
        json={
            "run_id": run["id"],
            "subject": "alice",
            "capability": Capability.SECRET_READ.value,
            "resource": "ads-client-secret",
        },
    )
    assert denied.json()["effect"] == Effect.DENY.value
    assert denied.json()["message"] == SETTINGS.denied_message


def test_an_unknown_run_is_denied(api: TestClient) -> None:
    response = api.post(
        "/policy/decide",
        json={
            "run_id": "nope",
            "subject": "alice",
            "capability": Capability.DB_QUERY.value,
            "resource": "select 1",
        },
    )
    assert response.json()["effect"] == Effect.DENY.value
    assert response.json()["rule_id"] == "run.unknown"


def test_a_run_belongs_to_one_subject(api: TestClient) -> None:
    run = _start(api, subject="alice")
    response = api.post(
        "/policy/decide",
        json={
            "run_id": run["id"],
            "subject": "bob",
            "capability": Capability.DB_QUERY.value,
            "resource": "select 1",
        },
    )
    assert response.json()["rule_id"] == "run.subject"


def test_revocation_takes_effect_on_the_next_call(api: TestClient) -> None:
    run = _start(api)
    query = {
        "run_id": run["id"],
        "subject": "alice",
        "capability": Capability.DB_QUERY.value,
        "resource": "select 1",
    }
    assert api.post("/policy/decide", json=query).json()["effect"] == Effect.ALLOW.value
    revoked = api.post(f"/policy/runs/{run['id']}/revoke")
    assert revoked.status_code == 201
    assert revoked.json()["state"] == "revoked"
    assert api.post("/policy/decide", json=query).json()["rule_id"] == "run.state"


def test_revoking_an_unknown_run_is_not_found(api: TestClient) -> None:
    assert api.post("/policy/runs/nope/revoke").status_code == 404


def test_the_service_reads_a_mounted_policy(tmp_path: Path, redis: Redis) -> None:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    (policy_dir / "policy.yaml").write_text("version: org-mounted\nrules: []\n")
    settings = Settings(
        api_token=TOKEN,
        tls_cert_path=cert,
        tls_key_path=key,
        redis_url="redis://unused",
        amqp_url="amqp://unused",
        governance=GovernanceSettings(policy_dir=policy_dir),
    )
    with TestClient(app=create_app(settings, redis, CollectingAuditSink())) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        assert client.get("/policy/version").json()["version"] == "org-mounted"
