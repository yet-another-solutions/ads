from __future__ import annotations

import os
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID


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
    kafka_bootstrap_servers: str = ""
    engine_request_topic: str = "ads.engine.request"
    engine_output_topic: str = "ads.engine.output"
    engine_consumer_group: str = "ads"
    preferences_base_url: str = "https://ads-preferences.invalid"
    preferences_audience: str = "ads-preferences"
    engine_audience: str = "ads-engine"
    engine_allowed_azp: str = "ads-engine"
    ping_death_seconds: float = 30.0
    finish_gap_seconds: float = 10.0
    watchdog_tick_seconds: float = 1.0
    sandbox_manager_base_url: str = "https://ads-sandbox-manager.invalid"
    manager_service_subject: UUID | None = None
    ipc_service_subject: UUID | None = None
    egress_consumer_group: str = "ads-egress-config"
    kafka_security_protocol: str = "PLAINTEXT"
    kafka_sasl_mechanism: str = "SCRAM-SHA-512"
    kafka_sasl_username: str | None = None
    kafka_sasl_password: str | None = field(default=None, repr=False)
    kafka_ca_bundle: Path | None = None

    def kafka_options(self) -> dict[str, Any]:
        if self.kafka_security_protocol not in ("PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL"):
            raise ValueError("unsupported Kafka security protocol")
        options: dict[str, Any] = {
            "bootstrap_servers": self.kafka_bootstrap_servers,
            "security_protocol": self.kafka_security_protocol,
        }
        if self.kafka_security_protocol.startswith("SASL"):
            if not self.kafka_sasl_username or not self.kafka_sasl_password:
                raise ValueError("Kafka SASL credentials required")
            options.update(
                sasl_mechanism=self.kafka_sasl_mechanism,
                sasl_plain_username=self.kafka_sasl_username,
                sasl_plain_password=self.kafka_sasl_password,
            )
        if self.kafka_security_protocol.endswith("SSL"):
            options["ssl_context"] = ssl.create_default_context(cafile=self.kafka_ca_bundle)
        return options

    def session_secret_bytes(self) -> bytes:
        if not self.session_secret.strip():
            raise RuntimeError("ADS_SESSION_SECRET must be non-empty")
        encoded = self.session_secret.encode("utf-8")
        if len(encoded) < 16:
            raise RuntimeError("ADS_SESSION_SECRET must be at least 16 bytes")
        return encoded[:32].ljust(32, b"\0")

    def cookie_secure(self) -> bool:
        return self.public_base_url.startswith("https://")


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
        session_secret=session_secret,
        public_base_url=_env("ADS_PUBLIC_BASE_URL").rstrip("/"),
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        tls_ca_bundle=ca_bundle,
        bind_host=_env("ADS_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_PORT", "8080")),
        database_url=_env("ADS_DATABASE_URL"),
        kafka_bootstrap_servers=_env("ADS_KAFKA_BOOTSTRAP_SERVERS"),
        engine_request_topic=_env("ADS_ENGINE_REQUEST_TOPIC", "ads.engine.request"),
        engine_output_topic=_env("ADS_ENGINE_OUTPUT_TOPIC", "ads.engine.output"),
        engine_consumer_group=_env("ADS_ENGINE_CONSUMER_GROUP", "ads"),
        preferences_base_url=_env("ADS_PREFERENCES_BASE_URL").rstrip("/"),
        preferences_audience=_env("ADS_PREFERENCES_AUDIENCE", "ads-preferences"),
        engine_audience=_env("ADS_ENGINE_AUDIENCE", "ads-engine"),
        engine_allowed_azp=_env("ADS_ENGINE_ALLOWED_AZP", "ads-engine"),
        sandbox_manager_base_url=_env("ADS_SANDBOX_MANAGER_BASE_URL").rstrip("/"),
        manager_service_subject=UUID(_env("ADS_MANAGER_SERVICE_SUBJECT")),
        ipc_service_subject=UUID(_env("ADS_IPC_SERVICE_SUBJECT")),
        kafka_security_protocol=_env("ADS_KAFKA_SECURITY_PROTOCOL", "PLAINTEXT"),
        kafka_sasl_mechanism=_env("ADS_KAFKA_SASL_MECHANISM", "SCRAM-SHA-512"),
        kafka_sasl_username=os.environ.get("ADS_KAFKA_SASL_USERNAME"),
        kafka_sasl_password=os.environ.get("ADS_KAFKA_SASL_PASSWORD"),
        kafka_ca_bundle=Path(os.environ["ADS_KAFKA_CA_BUNDLE"])
        if os.environ.get("ADS_KAFKA_CA_BUNDLE")
        else None,
    )
    load_tls_context(settings)
    return settings
