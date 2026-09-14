from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"{name} is required")
    return value


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


def load_settings() -> Settings:
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
    )
