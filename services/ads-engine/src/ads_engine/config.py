from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


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
    ack_timeout_seconds: float
    keycloak_well_known_url: str
    keycloak_issuer: str
    keycloak_audience: str
    keycloak_client_id: str
    keycloak_client_secret: str
    ack_audience: str
    allowed_callers: frozenset[str]
    tls_ca_bundle: Path | None
    mcp_url: str = "https://ads-sandbox-mcp:8443/mcp"
    mcp_timeout_seconds: float = 120
    max_tool_calls: int = 32
    context_meter_url: str = "https://ads-context-meter:8443/meter"
    context_compactor_url: str = "https://ads-context-compactor:8443/compact"
    context_trigger: int = 80
    context_target: int = 50
    context_output_reserve: int = 1024

    def __post_init__(self) -> None:
        url = urlsplit(self.mcp_url)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.fragment
        ):
            raise ValueError("ADS_ENGINE_MCP_URL must be an HTTPS endpoint without credentials")
        if not math.isfinite(self.mcp_timeout_seconds) or self.mcp_timeout_seconds <= 0:
            raise ValueError("ADS_ENGINE_MCP_TIMEOUT_SECONDS must be positive and finite")
        if self.max_tool_calls < 1:
            raise ValueError("ADS_ENGINE_MAX_TOOL_CALLS must be positive")
        for endpoint in (self.context_meter_url, self.context_compactor_url):
            parsed = urlsplit(endpoint)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ValueError("context service URLs must be HTTPS without credentials")
        if not 0 < self.context_target < self.context_trigger < 100:
            raise ValueError("context target must be below trigger, both percentages")
        if self.context_output_reserve <= 0:
            raise ValueError("context output reserve must be positive")


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
        database_url=_env("ADS_ENGINE_DATABASE_URL"),
        ping_interval_seconds=float(_env("ADS_ENGINE_PING_INTERVAL_SECONDS", "10")),
        ack_timeout_seconds=float(_env("ADS_ENGINE_ACK_TIMEOUT_SECONDS", "10")),
        keycloak_well_known_url=_env("ADS_ENGINE_KEYCLOAK_WELL_KNOWN_URL"),
        keycloak_issuer=_env("ADS_ENGINE_KEYCLOAK_ISSUER"),
        keycloak_audience=_env("ADS_ENGINE_KEYCLOAK_AUDIENCE", "ads-engine"),
        keycloak_client_id=_env("ADS_ENGINE_KEYCLOAK_CLIENT_ID", "ads"),
        keycloak_client_secret=_env("ADS_ENGINE_KEYCLOAK_CLIENT_SECRET"),
        ack_audience=_env("ADS_ENGINE_ACK_AUDIENCE", "ads"),
        allowed_callers=_callers(_env("ADS_ENGINE_ALLOWED_CALLERS", "ads")),
        tls_ca_bundle=tls_ca_bundle,
        mcp_url=_env("ADS_ENGINE_MCP_URL", "https://ads-sandbox-mcp:8443/mcp"),
        mcp_timeout_seconds=float(_env("ADS_ENGINE_MCP_TIMEOUT_SECONDS", "120")),
        max_tool_calls=int(_env("ADS_ENGINE_MAX_TOOL_CALLS", "32")),
        context_meter_url=_env(
            "ADS_ENGINE_CONTEXT_METER_URL", "https://ads-context-meter:8443/meter"
        ),
        context_compactor_url=_env(
            "ADS_ENGINE_CONTEXT_COMPACTOR_URL", "https://ads-context-compactor:8443/compact"
        ),
        context_trigger=int(_env("ADS_ENGINE_CONTEXT_TRIGGER", "80")),
        context_target=int(_env("ADS_ENGINE_CONTEXT_TARGET", "50")),
        context_output_reserve=int(_env("ADS_ENGINE_CONTEXT_OUTPUT_RESERVE", "1024")),
    )
