from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    keycloak_well_known_url: str
    keycloak_issuer: str
    keycloak_client_secret: str
    tls_cert_path: Path
    tls_key_path: Path
    tls_ca_bundle: Path | None = None
    keycloak_audience: str = "ads-context-compactor"
    keycloak_client_id: str = "ads-context-compactor"
    meter_url: str = "https://ads-context-meter:8443/meter"
    bind_host: str = "0.0.0.0"
    port: int = 8080
    reserve: int = 1024
    summary_cap: int = 2048
    completion_cap: int = 2048
    starvation_percentage: int = 10
    recall_reserve: int = 1024
    recall_answer_cap: int = 1024
    recall_completion_cap: int | None = None
    recall_starvation_percentage: int = 10
    minimum_reduction_percentage: int = 10

    def __post_init__(self) -> None:
        if (
            min(
                self.reserve,
                self.summary_cap,
                self.completion_cap,
                self.recall_reserve,
                self.recall_answer_cap,
            )
            <= 0
            or (self.recall_completion_cap is not None and self.recall_completion_cap <= 0)
            or not 0 < self.recall_starvation_percentage < 100
            or not 0 < self.starvation_percentage < 100
            or not 0 < self.minimum_reduction_percentage < 100
            or not 0 < self.port <= 65535
        ):
            raise ValueError("invalid compactor budgets or port")
        for endpoint in (self.meter_url, self.keycloak_well_known_url, self.keycloak_issuer):
            url = urlsplit(endpoint)
            if (
                url.scheme != "https"
                or not url.hostname
                or url.username
                or url.password
                or url.fragment
            ):
                raise ValueError("context service URLs must be HTTPS without credentials")


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    ssl.create_default_context(cafile=settings.tls_ca_bundle)
    return context


def load_settings() -> Settings:
    prefix = "ADS_CONTEXT_COMPACTOR_"

    def env(name: str, default: str | None = None) -> str:
        value = os.environ.get(prefix + name, default)
        if not value:
            raise RuntimeError(prefix + name + " is required")
        return value

    ca = os.environ.get(prefix + "TLS_CA_BUNDLE")
    recall_cap = os.environ.get(prefix + "RECALL_COMPLETION_CAP_TOKENS", "").strip()
    settings = Settings(
        keycloak_well_known_url=env("KEYCLOAK_WELL_KNOWN_URL"),
        keycloak_issuer=env("KEYCLOAK_ISSUER"),
        keycloak_client_secret=env("KEYCLOAK_CLIENT_SECRET"),
        keycloak_audience=env("KEYCLOAK_AUDIENCE", "ads-context-compactor"),
        keycloak_client_id=env("KEYCLOAK_CLIENT_ID", "ads-context-compactor"),
        tls_cert_path=Path(env("TLS_CERT_PATH")),
        tls_key_path=Path(env("TLS_KEY_PATH")),
        tls_ca_bundle=Path(ca) if ca else None,
        meter_url=env("METER_URL", "https://ads-context-meter:8443/meter"),
        bind_host=env("BIND_HOST", "0.0.0.0"),
        port=int(env("PORT", "8080")),
        reserve=int(env("RESERVED_OUTPUT_TOKENS", "1024")),
        summary_cap=int(env("SUMMARY_CAP_TOKENS", "2048")),
        completion_cap=int(env("COMPLETION_CAP_TOKENS", "2048")),
        starvation_percentage=int(env("STARVATION_PERCENTAGE", "10")),
        recall_reserve=int(env("RECALL_RESERVED_OUTPUT_TOKENS", "1024")),
        recall_answer_cap=int(env("RECALL_ANSWER_CAP_TOKENS", "1024")),
        recall_completion_cap=int(recall_cap) if recall_cap else None,
        recall_starvation_percentage=int(env("RECALL_STARVATION_PERCENTAGE", "10")),
        minimum_reduction_percentage=int(env("MINIMUM_REDUCTION_PERCENTAGE", "10")),
    )
    load_tls_context(settings)
    return settings
