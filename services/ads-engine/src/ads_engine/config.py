from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"{name} is required")
    return value


def _callers(raw: str) -> frozenset[str]:
    parties = frozenset(part.strip() for part in raw.split(",") if part.strip())
    if not parties:
        raise RuntimeError("ADS_ENGINE_ALLOWED_CALLERS must list at least one caller")
    return parties


@dataclass(frozen=True, slots=True)
class Settings:
    kafka_bootstrap_servers: str
    request_topic: str
    output_topic: str
    consumer_group: str
    database_url: str
    ping_interval_seconds: float
    keycloak_well_known_url: str
    keycloak_issuer: str
    keycloak_audience: str
    keycloak_client_id: str
    allowed_callers: frozenset[str]
    tls_ca_bundle: Path | None


def load_settings() -> Settings:
    ca_raw = os.environ.get("ADS_ENGINE_TLS_CA_BUNDLE", "").strip()
    tls_ca_bundle = Path(ca_raw) if ca_raw else None
    if tls_ca_bundle is not None and not tls_ca_bundle.is_file():
        raise RuntimeError("ADS_ENGINE_TLS_CA_BUNDLE must exist")
    return Settings(
        kafka_bootstrap_servers=_env("ADS_ENGINE_KAFKA_BOOTSTRAP_SERVERS"),
        request_topic=_env("ADS_ENGINE_REQUEST_TOPIC", "ads.engine.request"),
        output_topic=_env("ADS_ENGINE_OUTPUT_TOPIC", "ads.engine.output"),
        consumer_group=_env("ADS_ENGINE_CONSUMER_GROUP", "ads-engine"),
        database_url=_env("ADS_ENGINE_DATABASE_URL", "sqlite:////tmp/ads-engine.db"),
        ping_interval_seconds=float(_env("ADS_ENGINE_PING_INTERVAL_SECONDS", "10")),
        keycloak_well_known_url=_env("ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL"),
        keycloak_issuer=_env("ADS_ENGINE_KEYCLOAK_ISSUER"),
        keycloak_audience=_env("ADS_ENGINE_KEYCLOAK_AUDIENCE", "ads-engine"),
        keycloak_client_id=_env("ADS_ENGINE_KEYCLOAK_CLIENT_ID", "ads"),
        allowed_callers=_callers(_env("ADS_ENGINE_ALLOWED_CALLERS", "ads")),
        tls_ca_bundle=tls_ca_bundle,
    )
