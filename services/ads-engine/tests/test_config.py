from __future__ import annotations

from pathlib import Path

import pytest

from ads_engine.config import load_settings


def test_load_settings_keeps_keycloak_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS", "kafka.example:9092")
    monkeypatch.setenv(
        "ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL",
        "https://auth.example/realms/ads/.well-known/openid-configuration",
    )
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_ISSUER", "https://auth.example/realms/ads")
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_AUDIENCE", "ads-engine")
    settings = load_settings()
    assert settings.kafka_bootstrap_servers == "kafka.example:9092"
    assert settings.request_topic == "ads.engine.request"
    assert settings.output_topic == "ads.engine.output"
    assert settings.consumer_group == "ads-engine"
    assert settings.keycloak_issuer == "https://auth.example/realms/ads"
    assert settings.keycloak_audience == "ads-engine"
    assert settings.keycloak_client_id == "ads"
    assert settings.tls_ca_bundle is None
    assert settings.ping_interval_seconds == 10


def test_load_settings_requires_keycloak_issuer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS", "kafka.example:9092")
    monkeypatch.setenv(
        "ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL",
        "https://auth.example/realms/ads/.well-known/openid-configuration",
    )
    monkeypatch.delenv("ADS_ENGINE_KEYCLOAK_ISSUER", raising=False)
    with pytest.raises(RuntimeError, match="ADS_ENGINE_KEYCLOAK_ISSUER"):
        load_settings()


def test_load_settings_requires_ca_bundle_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS", "kafka.example:9092")
    monkeypatch.setenv(
        "ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL",
        "https://auth.example/realms/ads/.well-known/openid-configuration",
    )
    monkeypatch.setenv("ADS_ENGINE_KEYCLOAK_ISSUER", "https://auth.example/realms/ads")
    monkeypatch.setenv("ADS_ENGINE_TLS_CA_BUNDLE", str(tmp_path / "missing.crt"))
    with pytest.raises(RuntimeError, match="ADS_ENGINE_TLS_CA_BUNDLE"):
        load_settings()
