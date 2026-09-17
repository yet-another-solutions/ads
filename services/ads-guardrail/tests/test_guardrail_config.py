from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ads_guardrail.config import _applications, _mcp_servers, load_settings
from ads_policy.contract import Placement

KEY_SHA256 = "a" * 64
WORKSPACE: dict[str, Any] = {
    "project": "ads",
    "repo": "yet-another-solutions/ads",
    "env": "test",
    "workdir": "/workspace",
}
HERMES: dict[str, Any] = {"name": "hermes", "key_sha256": KEY_SHA256, "workspace": WORKSPACE}
KATA_SITE: dict[str, Any] = {
    "placement": "cluster",
    "runtime_class_name": "kata-clh",
    "node_labels": {"ads.io/sandbox-node": "true", "ads.io/application-node": "true"},
}
SANDBOX_SERVER: dict[str, Any] = {
    "name": "sandbox",
    "url": "http://ads-sandbox-mcp:8080/mcp/",
    "site": KATA_SITE,
}


def _minimal_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)


@pytest.mark.parametrize("missing", ["ADS_KEYCLOAK_WELL_KNOWN_URL", "ADS_KEYCLOAK_ISSUER"])
def test_audience_without_keycloak_stops_the_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, missing: str
) -> None:
    _minimal_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("ADS_MCP_AUDIENCE", "ads-mcp")
    monkeypatch.setenv(
        "ADS_KEYCLOAK_WELL_KNOWN_URL", "https://keycloak.test/.well-known/openid-configuration"
    )
    monkeypatch.setenv("ADS_KEYCLOAK_ISSUER", "https://keycloak.test/realms/ads")
    monkeypatch.delenv(missing)
    with pytest.raises(RuntimeError, match="ADS_MCP_AUDIENCE needs"):
        load_settings()


def test_the_injection_scanner_is_read_with_its_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _minimal_environment(monkeypatch, tmp_path)
    monkeypatch.setattr("ads_guardrail.config.load_tls_context", lambda settings: None)
    monkeypatch.setenv("ADS_INJECTION_SCANNER_URL", "https://scanner.test/")
    monkeypatch.setenv("ADS_INJECTION_SCANNER_API_TOKEN", "scanner-api-token")
    settings = load_settings()
    assert settings.injection_scanner_url == "https://scanner.test"
    assert settings.injection_scanner_api_token == "scanner-api-token"


@pytest.mark.parametrize("only", ["ADS_INJECTION_SCANNER_URL", "ADS_INJECTION_SCANNER_API_TOKEN"])
def test_a_scanner_address_without_a_token_stops_the_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, only: str
) -> None:
    _minimal_environment(monkeypatch, tmp_path)
    monkeypatch.setenv(only, "https://scanner.test")
    with pytest.raises(RuntimeError, match="go together"):
        load_settings()


def test_applications_are_read_from_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_APPLICATIONS", json.dumps([HERMES]))
    (hermes,) = _applications()
    assert hermes.name == "hermes"
    assert hermes.key_sha256 == KEY_SHA256
    assert hermes.workspace.project == "ads"


def test_no_applications_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADS_APPLICATIONS", raising=False)
    assert _applications() == ()


@pytest.mark.parametrize(
    ("applications", "message"),
    [
        ("not json", "unreadable"),
        ([{**HERMES, "workspace": {"project": "ads"}}], "unreadable"),
        ([{**HERMES, "name": " "}], "needs a name"),
        ([{**HERMES, "key_sha256": "the-key-itself"}], "64 lowercase hex"),
        ([{**HERMES, "key_sha256": KEY_SHA256.upper()}], "64 lowercase hex"),
        ([HERMES, {**HERMES, "name": "other"}], "reuses another's key"),
    ],
)
def test_invalid_application_stops_the_service(
    monkeypatch: pytest.MonkeyPatch, applications: object, message: str
) -> None:
    raw = applications if isinstance(applications, str) else json.dumps(applications)
    monkeypatch.setenv("ADS_APPLICATIONS", raw)
    with pytest.raises(RuntimeError, match=message):
        _applications()


def test_mcp_servers_are_read_with_their_sites(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_MCP_SERVERS", json.dumps([SANDBOX_SERVER]))
    (sandbox,) = _mcp_servers()
    assert sandbox.name == "sandbox"
    assert sandbox.url == "http://ads-sandbox-mcp:8080/mcp"
    assert sandbox.site.placement is Placement.CLUSTER
    assert sandbox.site.runtime_class_name == "kata-clh"


def test_no_mcp_servers_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADS_MCP_SERVERS", raising=False)
    assert _mcp_servers() == ()


@pytest.mark.parametrize(
    ("servers", "message"),
    [
        ("not json", "unreadable"),
        ([{"name": "sandbox", "url": "http://x/mcp"}], "unreadable"),
        ([{**SANDBOX_SERVER, "name": "sand/box"}], "not usable as a path segment"),
        ([{**SANDBOX_SERVER, "url": "ads-sandbox-mcp:8080/mcp"}], "needs an http"),
        ([SANDBOX_SERVER, SANDBOX_SERVER], "listed twice"),
    ],
)
def test_invalid_mcp_server_stops_the_service(
    monkeypatch: pytest.MonkeyPatch, servers: object, message: str
) -> None:
    raw = servers if isinstance(servers, str) else json.dumps(servers)
    monkeypatch.setenv("ADS_MCP_SERVERS", raw)
    with pytest.raises(RuntimeError, match=message):
        _mcp_servers()
