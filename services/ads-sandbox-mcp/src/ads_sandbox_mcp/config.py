from __future__ import annotations

import math
import os
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str = field(repr=False)
    keycloak_well_known_url: str
    keycloak_issuer: str
    keycloak_client_secret: str = field(repr=False)
    tls_cert_path: Path
    tls_key_path: Path
    kafka_bootstrap_servers: str
    tls_ca_bundle: Path | None = None
    bind_host: str = "0.0.0.0"
    port: int = 8080
    timeout_seconds: float = 120
    stdout_bytes: int = 65536
    stderr_bytes: int = 65536
    input_bytes: int = 262144
    allowed_hosts: tuple[str, ...] = ("ads-sandbox-mcp:*", "ads-sandbox-mcp")
    allowed_origins: tuple[str, ...] = ()
    allowed_callers: tuple[str, ...] = ("ads-engine",)
    request_topic: str = "ads.sandbox.exec.request"
    reply_topic: str = "ads.sandbox.exec.reply"
    kafka_security_protocol: str = "PLAINTEXT"
    kafka_sasl_mechanism: str = "PLAIN"
    kafka_sasl_username: str | None = None
    kafka_sasl_password: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        if min(self.stdout_bytes, self.stderr_bytes, self.input_bytes) <= 0:
            raise ValueError("input and output caps must be positive")
        if not self.database_url.startswith("postgresql+psycopg://"):
            raise ValueError("ADS sandbox MCP requires dedicated PostgreSQL via psycopg")
        if not self.allowed_hosts:
            raise ValueError("allowed_hosts must not be empty")
        if not self.allowed_callers:
            raise ValueError("allowed_callers must name who may reach the sandbox")
        if self.kafka_security_protocol not in ("PLAINTEXT", "SASL_PLAINTEXT"):
            raise ValueError("unsupported Kafka security protocol")
        if self.kafka_security_protocol == "SASL_PLAINTEXT" and not (
            self.kafka_sasl_username and self.kafka_sasl_password
        ):
            raise ValueError("Kafka SASL username and password are required")

    def kafka_options(self) -> dict[str, Any]:
        return {
            "bootstrap_servers": self.kafka_bootstrap_servers,
            "security_protocol": self.kafka_security_protocol,
            "sasl_mechanism": self.kafka_sasl_mechanism,
            "sasl_plain_username": self.kafka_sasl_username,
            "sasl_plain_password": self.kafka_sasl_password,
        }


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    if settings.tls_ca_bundle is not None:
        ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
    return context


def load_settings() -> Settings:
    prefix = "ADS_SANDBOX_MCP_"

    def required(name: str) -> str:
        value = os.environ.get(prefix + name, "").strip()
        if not value:
            raise RuntimeError(f"{prefix}{name} is required")
        return value

    def csv(name: str, default: str) -> tuple[str, ...]:
        return tuple(
            x.strip() for x in os.environ.get(prefix + name, default).split(",") if x.strip()
        )

    ca = os.environ.get(prefix + "TLS_CA_BUNDLE", "").strip()
    settings = Settings(
        database_url=required("DATABASE_URL"),
        keycloak_well_known_url=required("KEYCLOAK_WELL_KNOWN_URL"),
        keycloak_issuer=required("KEYCLOAK_ISSUER"),
        keycloak_client_secret=required("KEYCLOAK_CLIENT_SECRET"),
        tls_cert_path=Path(required("TLS_CERT_PATH")),
        tls_key_path=Path(required("TLS_KEY_PATH")),
        kafka_bootstrap_servers=required("KAFKA_BOOTSTRAP_SERVERS"),
        kafka_security_protocol=os.environ.get(prefix + "KAFKA_SECURITY_PROTOCOL", "PLAINTEXT"),
        kafka_sasl_mechanism=os.environ.get(prefix + "KAFKA_SASL_MECHANISM", "PLAIN"),
        kafka_sasl_username=os.environ.get(prefix + "KAFKA_SASL_USERNAME"),
        kafka_sasl_password=os.environ.get(prefix + "KAFKA_SASL_PASSWORD"),
        tls_ca_bundle=Path(ca) if ca else None,
        bind_host=os.environ.get(prefix + "BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get(prefix + "PORT", "8080")),
        timeout_seconds=float(os.environ.get(prefix + "TIMEOUT_SECONDS", "120")),
        stdout_bytes=int(os.environ.get(prefix + "STDOUT_BYTES", "65536")),
        stderr_bytes=int(os.environ.get(prefix + "STDERR_BYTES", "65536")),
        input_bytes=int(os.environ.get(prefix + "INPUT_BYTES", "262144")),
        allowed_hosts=csv("ALLOWED_HOSTS", "ads-sandbox-mcp,ads-sandbox-mcp:*"),
        allowed_origins=csv("ALLOWED_ORIGINS", ""),
        allowed_callers=csv("ALLOWED_CALLERS", "ads-engine"),
    )
    load_tls_context(settings)
    return settings
