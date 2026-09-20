from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from ads_engine.config import load_settings


def test_load_settings_reads_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_text("ca", encoding="utf-8")
    monkeypatch.setenv("ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    monkeypatch.setenv("ADS_ENGINE_REQUEST_TOPIC", "ads.engine.request")
    monkeypatch.setenv("ADS_ENGINE_OUTPUT_TOPIC", "ads.engine.output")
    monkeypatch.setenv("ADS_ENGINE_CONSUMER_GROUP", "ads-engine")
    monkeypatch.setenv(
        "ADS_ENGINE_DATABASE_URL",
        "postgresql+psycopg://ads_engine@db/ads_engine",
    )
    monkeypatch.setenv("ADS_ENGINE_PING_INTERVAL_SECONDS", "7")
    monkeypatch.setenv("ADS_ENGINE_ACK_TIMEOUT_SECONDS", "12")
    monkeypatch.setenv(
        "ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL",
        "https://keycloak.test/realms/ads/.well-known/openid-configuration",
    )
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_ISSUER", "https://keycloak.test/realms/ads")
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_AUDIENCE", "ads-engine")
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_CLIENT_ID", "ads")
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_CLIENT_SECRET", "engine-client-secret")
    monkeypatch.setenv("ADS_ENGINE_ACK_AUDIENCE", "ads")
    monkeypatch.setenv("ADS_ENGINE_ALLOWED_CALLERS", "ads, ads-ui")
    monkeypatch.setenv("ADS_ENGINE_TLS_CA_BUNDLE", str(ca))
    monkeypatch.setenv("ADS_ENGINE_MCP_URL", "https://sandbox.test/mcp")
    monkeypatch.setenv("ADS_ENGINE_MCP_TIMEOUT_SECONDS", "90")
    monkeypatch.setenv("ADS_ENGINE_MAX_TOOL_CALLS", "12")
    monkeypatch.setenv("ADS_ENGINE_CONTEXT_TRIGGER", "75")
    monkeypatch.setenv("ADS_ENGINE_CONTEXT_TARGET", "40")
    monkeypatch.setenv("ADS_ENGINE_INNER_RECALL_RESERVED_OUTPUT_TOKENS", "512")
    monkeypatch.setenv("ADS_ENGINE_INNER_RECALL_ANSWER_CAP_TOKENS", "768")
    monkeypatch.setenv("ADS_ENGINE_INNER_RECALL_COMPLETION_CAP_TOKENS", "8192")
    monkeypatch.setenv("ADS_ENGINE_INNER_RECALL_STARVATION_PERCENTAGE", "15")
    monkeypatch.setenv("ADS_ENGINE_TOP_LEVEL_RECALL_RESERVED_OUTPUT_TOKENS", "256")
    monkeypatch.setenv("ADS_ENGINE_TOP_LEVEL_RECALL_ANSWER_CAP_TOKENS", "1536")
    monkeypatch.setenv("ADS_ENGINE_TOP_LEVEL_RECALL_COMPLETION_CAP_TOKENS", "4096")
    monkeypatch.setenv("ADS_ENGINE_TOP_LEVEL_RECALL_STARVATION_PERCENTAGE", "20")

    settings = load_settings()

    assert settings.kafka_bootstrap_servers == "kafka:9092"
    assert settings.database_url == "postgresql+psycopg://ads_engine@db/ads_engine"
    assert settings.ping_interval_seconds == 7
    assert settings.ack_timeout_seconds == 12
    assert settings.keycloak_client_secret == "engine-client-secret"
    assert settings.ack_audience == "ads"
    assert settings.allowed_callers == frozenset({"ads", "ads-ui"})
    assert settings.tls_ca_bundle == ca
    assert settings.mcp_url == "https://sandbox.test/mcp"
    assert settings.mcp_timeout_seconds == 90
    assert settings.max_tool_calls == 12
    assert settings.context_trigger == 75
    assert settings.context_target == 40
    assert settings.recall_reserve == 512
    assert settings.recall_answer_cap == 768
    assert settings.recall_completion_cap == 8192
    assert settings.recall_starvation_percentage == 15

    from ads_engine.context import EngineContextFactory
    from engine_fakes import make_request

    context = EngineContextFactory(replace(settings, tls_ca_bundle=None), None).open(make_request())
    assert context.trigger == 75 and context.target == 40
    assert context.recall.reserve == 512
    assert context.recall.answer_cap == 768
    assert context.recall.answer_completion_cap == 8192
    assert context.recall.starvation_percentage == 15
    assert context.recall.top_level_reserve == 256
    assert context.recall.top_level_answer_cap == 1536
    assert context.recall.top_level_completion_cap == 4096
    assert context.recall.top_level_starvation_percentage == 20


@pytest.mark.parametrize(
    "changes",
    [
        {"mcp_url": "http://sandbox.test/mcp"},
        {"mcp_url": "https://user:secret@sandbox.test/mcp"},
        {"mcp_url": "https://sandbox.test/mcp#fragment"},
        {"mcp_url": "https:///mcp"},
        {"mcp_timeout_seconds": 0},
        {"mcp_timeout_seconds": float("nan")},
        {"mcp_timeout_seconds": float("inf")},
        {"max_tool_calls": 0},
        {"context_target": 80},
        {"context_trigger": 100},
        {"recall_reserve": 0},
        {"recall_answer_cap": 0},
        {"recall_completion_cap": -1},
        {"recall_starvation_percentage": 0},
        {"recall_starvation_percentage": 100},
        {"top_level_recall_reserve": 0},
        {"top_level_recall_answer_cap": 0},
        {"top_level_recall_completion_cap": 0},
        {"top_level_recall_starvation_percentage": 0},
        {"top_level_recall_starvation_percentage": 100},
    ],
)
def test_mcp_settings_fail_closed(settings, changes):
    with pytest.raises(ValueError):
        replace(settings, **changes)


def test_ack_timeout_defaults_to_ten_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    monkeypatch.setenv(
        "ADS_ENGINE_DATABASE_URL",
        "postgresql+psycopg://ads_engine@db/ads_engine",
    )
    monkeypatch.setenv(
        "ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL",
        "https://keycloak.test/realms/ads/.well-known/openid-configuration",
    )
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_ISSUER", "https://keycloak.test/realms/ads")
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_CLIENT_SECRET", "engine-client-secret")
    monkeypatch.delenv("ADS_ENGINE_ACK_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("ADS_ENGINE_ACK_AUDIENCE", raising=False)

    settings = load_settings()

    assert settings.ack_timeout_seconds == 10
    assert settings.ack_audience == "ads"


def _minimal_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    monkeypatch.setenv("ADS_ENGINE_DATABASE_URL", "postgresql+psycopg://ads_engine@db/ads_engine")
    monkeypatch.setenv(
        "ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL",
        "https://keycloak.test/realms/ads/.well-known/openid-configuration",
    )
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_ISSUER", "https://keycloak.test/realms/ads")
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_CLIENT_SECRET", "engine-client-secret")


def test_without_mcp_servers_there_are_no_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    _minimal_environment(monkeypatch)
    monkeypatch.delenv("ADS_ENGINE_MCP_SERVERS", raising=False)
    assert load_settings().tools is None


def test_mcp_servers_bring_the_tool_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    _minimal_environment(monkeypatch)
    monkeypatch.setenv("ADS_ENGINE_MCP_SERVERS", "probe, probe-vm")
    monkeypatch.setenv("ADS_ENGINE_GUARDRAIL_URL", "https://guardrail.test:8083/")
    monkeypatch.setenv("ADS_ENGINE_GUARDRAIL_API_TOKEN", "guardrail-api-token-32-bytes")
    monkeypatch.setenv("ADS_ENGINE_WORKSPACE_PROJECT", "ads")
    monkeypatch.setenv("ADS_ENGINE_WORKSPACE_REPO", "yet-another-solutions/ads")
    monkeypatch.setenv("ADS_ENGINE_WORKSPACE_ENV", "test")
    tools = load_settings().tools
    assert tools is not None
    assert tools.mcp_servers == ("probe", "probe-vm")
    assert tools.guardrail_url == "https://guardrail.test:8083"
    assert tools.mcp_audience == "ads-mcp"
    assert tools.workspace.workdir == "/workspace"
    assert tools.max_model_rounds == 8


@pytest.mark.parametrize(
    ("servers", "message"),
    [("probe,probe", "twice"), ("../etc", "not a server name")],
)
def test_malformed_mcp_servers_stop_the_engine(
    monkeypatch: pytest.MonkeyPatch, servers: str, message: str
) -> None:
    _minimal_environment(monkeypatch)
    monkeypatch.setenv("ADS_ENGINE_MCP_SERVERS", servers)
    with pytest.raises(RuntimeError, match=message):
        load_settings()


def test_mcp_servers_need_an_https_guardrail(monkeypatch: pytest.MonkeyPatch) -> None:
    _minimal_environment(monkeypatch)
    monkeypatch.setenv("ADS_ENGINE_MCP_SERVERS", "probe")
    monkeypatch.setenv("ADS_ENGINE_GUARDRAIL_URL", "http://guardrail.test")
    monkeypatch.setenv("ADS_ENGINE_GUARDRAIL_API_TOKEN", "guardrail-api-token-32-bytes")
    with pytest.raises(RuntimeError, match="https"):
        load_settings()


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    monkeypatch.setenv(
        "ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL",
        "https://keycloak.test/realms/ads/.well-known/openid-configuration",
    )
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_ISSUER", "https://keycloak.test/realms/ads")
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_CLIENT_SECRET", "engine-client-secret")
    monkeypatch.delenv("ADS_ENGINE_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="ADS_ENGINE_DATABASE_URL is required"):
        load_settings()
