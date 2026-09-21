from __future__ import annotations

from pathlib import Path

import pytest

from ads.config import Settings, load_settings, load_tls_context
from tests.certs import issue_tls, openssl_available


def test_load_settings_requires_tls_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(
        "ADS_KEYCLOAK_WELL_KNOWN_URL", "https://kc/realms/ads/.well-known/openid-configuration"
    )
    monkeypatch.setenv("ADS_KEYCLOAK_ISSUER", "https://kc/realms/ads")
    monkeypatch.setenv("ADS_KEYCLOAK_CLIENT_ID", "ads")
    monkeypatch.setenv("ADS_KEYCLOAK_CLIENT_SECRET", "secret")
    monkeypatch.setenv("ADS_SESSION_SECRET", "test-session-secret-32b!")
    monkeypatch.setenv("ADS_PUBLIC_BASE_URL", "https://ads.example")
    monkeypatch.setenv("ADS_TLS_CERT_PATH", str(tmp_path / "missing.crt"))
    monkeypatch.setenv("ADS_TLS_KEY_PATH", str(tmp_path / "missing.key"))
    with pytest.raises(RuntimeError, match="ADS_TLS_CERT_PATH must exist"):
        load_settings()


def test_load_tls_context_rejects_garbage_pem(tmp_path: Path) -> None:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("not-a-cert")
    key.write_text("not-a-key")
    settings = Settings(
        keycloak_well_known_url="https://kc/realms/ads/.well-known/openid-configuration",
        keycloak_issuer="https://kc/realms/ads",
        keycloak_client_id="ads",
        keycloak_client_secret="secret",
        keycloak_audience="ads",
        keycloak_role="user",
        session_secret="test-session-secret-32b!",
        public_base_url="https://ads.example",
        tls_cert_path=cert,
        tls_key_path=key,
        tls_ca_bundle=None,
        bind_host="127.0.0.1",
        port=8080,
    )
    with pytest.raises(RuntimeError, match="could not be loaded"):
        load_tls_context(settings)


@pytest.mark.skipif(not openssl_available(), reason="openssl required")
def test_load_settings_accepts_ca_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ca_crt, server_crt, server_key = issue_tls(tmp_path)
    monkeypatch.setenv(
        "ADS_KEYCLOAK_WELL_KNOWN_URL", "https://kc/realms/ads/.well-known/openid-configuration"
    )
    monkeypatch.setenv("ADS_KEYCLOAK_ISSUER", "https://kc/realms/ads")
    monkeypatch.setenv("ADS_KEYCLOAK_CLIENT_ID", "ads")
    monkeypatch.setenv("ADS_KEYCLOAK_CLIENT_SECRET", "secret")
    monkeypatch.setenv("ADS_SESSION_SECRET", "test-session-secret-32b!")
    monkeypatch.setenv("ADS_PUBLIC_BASE_URL", "https://ads.example")
    monkeypatch.setenv("ADS_TLS_CERT_PATH", str(server_crt))
    monkeypatch.setenv("ADS_TLS_KEY_PATH", str(server_key))
    monkeypatch.setenv("ADS_TLS_CA_BUNDLE", str(ca_crt))
    monkeypatch.setenv("ADS_DATABASE_URL", "postgresql+psycopg://ads@db/ads")
    monkeypatch.setenv("ADS_KAFKA_BOOTSTRAP_SERVERS", "kafka.test:9092")
    monkeypatch.setenv("ADS_PREFERENCES_BASE_URL", "https://ads-preferences.test/")
    settings = load_settings()
    assert settings.tls_ca_bundle == ca_crt
    assert settings.database_url == "postgresql+psycopg://ads@db/ads"
    assert settings.kafka_bootstrap_servers == "kafka.test:9092"
    assert settings.preferences_base_url == "https://ads-preferences.test"
    assert settings.engine_request_topic == "ads.engine.request"
    assert settings.engine_output_topic == "ads.engine.output"
    assert settings.engine_consumer_group == "ads"
    assert settings.preferences_audience == "ads-preferences"
    assert settings.engine_audience == "ads-engine"
    assert settings.engine_allowed_azp == "ads-engine"


@pytest.mark.skipif(not openssl_available(), reason="openssl required")
def test_load_settings_rejects_missing_ca_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, server_crt, server_key = issue_tls(tmp_path)
    monkeypatch.setenv(
        "ADS_KEYCLOAK_WELL_KNOWN_URL", "https://kc/realms/ads/.well-known/openid-configuration"
    )
    monkeypatch.setenv("ADS_KEYCLOAK_ISSUER", "https://kc/realms/ads")
    monkeypatch.setenv("ADS_KEYCLOAK_CLIENT_ID", "ads")
    monkeypatch.setenv("ADS_KEYCLOAK_CLIENT_SECRET", "secret")
    monkeypatch.setenv("ADS_SESSION_SECRET", "test-session-secret-32b!")
    monkeypatch.setenv("ADS_PUBLIC_BASE_URL", "https://ads.example")
    monkeypatch.setenv("ADS_TLS_CERT_PATH", str(server_crt))
    monkeypatch.setenv("ADS_TLS_KEY_PATH", str(server_key))
    monkeypatch.setenv("ADS_TLS_CA_BUNDLE", str(tmp_path / "missing-ca.crt"))
    with pytest.raises(RuntimeError, match="ADS_TLS_CA_BUNDLE must exist"):
        load_settings()


@pytest.mark.skipif(not openssl_available(), reason="openssl required")
def test_load_settings_requires_the_domain_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, server_crt, server_key = issue_tls(tmp_path)
    monkeypatch.setenv(
        "ADS_KEYCLOAK_WELL_KNOWN_URL", "https://kc/realms/ads/.well-known/openid-configuration"
    )
    monkeypatch.setenv("ADS_KEYCLOAK_ISSUER", "https://kc/realms/ads")
    monkeypatch.setenv("ADS_KEYCLOAK_CLIENT_ID", "ads")
    monkeypatch.setenv("ADS_KEYCLOAK_CLIENT_SECRET", "secret")
    monkeypatch.setenv("ADS_SESSION_SECRET", "test-session-secret-32b!")
    monkeypatch.setenv("ADS_PUBLIC_BASE_URL", "https://ads.example")
    monkeypatch.setenv("ADS_TLS_CERT_PATH", str(server_crt))
    monkeypatch.setenv("ADS_TLS_KEY_PATH", str(server_key))
    monkeypatch.delenv("ADS_TLS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("ADS_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="ADS_DATABASE_URL is required"):
        load_settings()
    monkeypatch.setenv("ADS_DATABASE_URL", "postgresql+psycopg://ads@db/ads")
    monkeypatch.delenv("ADS_KAFKA_BOOTSTRAP_SERVERS", raising=False)
    with pytest.raises(RuntimeError, match="ADS_KAFKA_BOOTSTRAP_SERVERS is required"):
        load_settings()
    monkeypatch.setenv("ADS_KAFKA_BOOTSTRAP_SERVERS", "kafka.test:9092")
    monkeypatch.delenv("ADS_PREFERENCES_BASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="ADS_PREFERENCES_BASE_URL is required"):
        load_settings()


def test_settings_defaults_keep_the_watchdog_deadlines(settings: Settings) -> None:
    assert settings.ping_death_seconds == 30.0
    assert settings.finish_gap_seconds == 10.0
    assert settings.watchdog_tick_seconds == 1.0
