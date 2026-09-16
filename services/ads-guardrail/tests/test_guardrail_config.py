from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ads_guardrail.config import _applications, _mcp_servers, load_settings
from ads_policy.contract import Placement

KEY = "a" * 64
HERMES: dict[str, Any] = {
    "name": "hermes",
    "key_sha256": KEY,
    "sandbox": {
        "project": "ads",
        "repo": "yet-another-solutions/ads",
        "env": "test",
        "workdir": "/workspace",
        "placement": "cluster",
        "node_labels": {"ads.io/application-node": "true"},
    },
}


@pytest.mark.parametrize("missing", ["ADS_KEYCLOAK_WELL_KNOWN_URL", "ADS_KEYCLOAK_ISSUER"])
def test_an_audience_without_keycloak_stops_the_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, missing: str
) -> None:
    """Tokens would be accepted with nothing to check them against."""
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    environment = {
        "ADS_TLS_CERT_PATH": str(cert),
        "ADS_TLS_KEY_PATH": str(key),
        "ADS_GUARDRAIL_API_TOKEN": "guardrail-api-token-32-bytes",
        "ADS_POLICY_URL": "https://policy.test",
        "ADS_POLICY_API_TOKEN": "policy-api-token",
        "ADS_AMQP_URL": "amqp://unused",
        "ADS_MCP_AUDIENCE": "ads-mcp",
        "ADS_KEYCLOAK_WELL_KNOWN_URL": "https://keycloak.test/.well-known/openid-configuration",
        "ADS_KEYCLOAK_ISSUER": "https://keycloak.test/realms/ads",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(missing)
    with pytest.raises(RuntimeError, match="ADS_MCP_AUDIENCE needs"):
        load_settings()


def test_applications_are_read_from_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_APPLICATIONS", json.dumps([HERMES]))
    (hermes,) = _applications()
    assert hermes.name == "hermes"
    assert hermes.key_sha256 == KEY
    assert hermes.sandbox.placement is Placement.CLUSTER


def test_no_applications_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADS_APPLICATIONS", raising=False)
    assert _applications() == ()


@pytest.mark.parametrize(
    ("applications", "message"),
    [
        ("not json", "unreadable"),
        ([{**HERMES, "sandbox": {"project": "ads"}}], "unreadable"),
        ([{**HERMES, "name": " "}], "needs a name"),
        ([{**HERMES, "key_sha256": "the-key-itself"}], "64 lowercase hex"),
        ([{**HERMES, "key_sha256": KEY.upper()}], "64 lowercase hex"),
        ([HERMES, {**HERMES, "name": "other"}], "reuses another's key"),
    ],
)
def test_a_bad_application_stops_the_service(
    monkeypatch: pytest.MonkeyPatch, applications: object, message: str
) -> None:
    """The key itself must never be what is configured, and a key names one application."""
    raw = applications if isinstance(applications, str) else json.dumps(applications)
    monkeypatch.setenv("ADS_APPLICATIONS", raw)
    with pytest.raises(RuntimeError, match=message):
        _applications()


def test_the_table_maps_names_to_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "ADS_MCP_SERVERS", "retriever=http://127.0.0.1:8006/mcp/, jira=https://jira.interlab/mcp"
    )
    assert _mcp_servers() == {
        "retriever": "http://127.0.0.1:8006/mcp",
        "jira": "https://jira.interlab/mcp",
    }


def test_an_empty_table_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The decision API still works; there is simply nothing to proxy."""
    monkeypatch.delenv("ADS_MCP_SERVERS", raising=False)
    assert _mcp_servers() == {}


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("re/triever=http://x/mcp", "not usable as a path segment"),
        ("retriever=127.0.0.1:8006/mcp", "needs an http"),
    ],
)
def test_a_bad_entry_stops_the_service(
    monkeypatch: pytest.MonkeyPatch, raw: str, message: str
) -> None:
    monkeypatch.setenv("ADS_MCP_SERVERS", raw)
    with pytest.raises(RuntimeError, match=message):
        _mcp_servers()
