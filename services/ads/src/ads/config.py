from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"{name} is required")
    return value


def _existing_file(name: str, raw: str) -> Path:
    path = Path(raw)
    if not path.is_file():
        raise RuntimeError(f"{name} must exist")
    return path


@dataclass(frozen=True, slots=True)
class Settings:
    keycloak_well_known_url: str
    keycloak_issuer: str
    keycloak_client_id: str
    keycloak_client_secret: str
    keycloak_audience: str
    keycloak_role: str
    session_secret: str
    public_base_url: str
    tls_cert_path: Path
    tls_key_path: Path
    tls_ca_bundle: Path | None
    bind_host: str
    port: int
    database_url: str = "sqlite:///:memory:"
    amqp_url: str = ""
    keycloak_auditor_role: str = "auditor"
    audit_flush_seconds: float = 1.0
    kafka_bootstrap_servers: str = ""
    engine_request_topic: str = "ads.engine.request"
    engine_output_topic: str = "ads.engine.output"
    engine_consumer_group: str = "ads"
    preferences_base_url: str = "https://ads-preferences.invalid"
    preferences_audience: str = "ads-preferences"
    engine_audience: str = "ads-engine"
    engine_allowed_azp: str = "ads-engine"
    auditor_allowed_azp: str = "ads-audit"
    ping_death_seconds: float = 30.0
    finish_gap_seconds: float = 10.0
    watchdog_tick_seconds: float = 1.0
    # Empty means no policy service is configured, and every decision then denies.
    policy_url: str = ""
    policy_api_token: str = ""


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    except ssl.SSLError as exc:
        raise RuntimeError("ADS TLS certificate and key could not be loaded") from exc
    if settings.tls_ca_bundle is not None:
        try:
            ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        except ssl.SSLError as exc:
            raise RuntimeError("ADS_TLS_CA_BUNDLE could not be loaded") from exc
    return context


@lru_cache
def load_settings() -> Settings:
    cert_path = _existing_file("ADS_TLS_CERT_PATH", _env("ADS_TLS_CERT_PATH").strip())
    key_path = _existing_file("ADS_TLS_KEY_PATH", _env("ADS_TLS_KEY_PATH").strip())
    ca_raw = os.environ.get("ADS_TLS_CA_BUNDLE", "").strip()
    ca_bundle = _existing_file("ADS_TLS_CA_BUNDLE", ca_raw) if ca_raw else None
    session_secret = _env("ADS_SESSION_SECRET")
    if not session_secret.strip():
        raise RuntimeError("ADS_SESSION_SECRET must be non-empty")
    settings = Settings(
        keycloak_well_known_url=_env("ADS_KEYCLOAK_WELL_KNOWN_URL"),
        keycloak_issuer=_env("ADS_KEYCLOAK_ISSUER"),
        keycloak_client_id=_env("ADS_KEYCLOAK_CLIENT_ID"),
        keycloak_client_secret=_env("ADS_KEYCLOAK_CLIENT_SECRET"),
        keycloak_audience=_env("ADS_KEYCLOAK_AUDIENCE", "ads"),
        keycloak_role=_env("ADS_KEYCLOAK_ROLE", "user"),
        keycloak_auditor_role=_env("ADS_KEYCLOAK_AUDITOR_ROLE", "auditor"),
        session_secret=session_secret,
        public_base_url=_env("ADS_PUBLIC_BASE_URL").rstrip("/"),
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        tls_ca_bundle=ca_bundle,
        bind_host=_env("ADS_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_PORT", "8080")),
        database_url=_env("ADS_DATABASE_URL"),
        amqp_url=_env("ADS_AMQP_URL", ""),
        kafka_bootstrap_servers=_env("ADS_KAFKA_BOOTSTRAP_SERVERS"),
        engine_request_topic=_env("ADS_ENGINE_REQUEST_TOPIC", "ads.engine.request"),
        engine_output_topic=_env("ADS_ENGINE_OUTPUT_TOPIC", "ads.engine.output"),
        engine_consumer_group=_env("ADS_ENGINE_CONSUMER_GROUP", "ads"),
        preferences_base_url=_env("ADS_PREFERENCES_BASE_URL").rstrip("/"),
        preferences_audience=_env("ADS_PREFERENCES_AUDIENCE", "ads-preferences"),
        engine_audience=_env("ADS_ENGINE_AUDIENCE", "ads-engine"),
        engine_allowed_azp=_env("ADS_ENGINE_ALLOWED_AZP", "ads-engine"),
        auditor_allowed_azp=_env("ADS_AUDITOR_ALLOWED_AZP", "ads-audit"),
        policy_url=_env("ADS_POLICY_URL", "").rstrip("/"),
        policy_api_token=_env("ADS_POLICY_API_TOKEN", ""),
    )
    load_tls_context(settings)
    return settings
