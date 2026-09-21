from __future__ import annotations

import math
import os
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class EgressPair:
    project_id: UUID
    base_url: str
    relay_urls: tuple[str, str]
    ads_service_subject: UUID


@dataclass(frozen=True, slots=True)
class Settings:
    sandbox_id: UUID
    pid_directory: Path
    keycloak_well_known_url: str
    keycloak_issuer: str
    keycloak_client_secret: str = field(repr=False)
    tls_cert_path: Path
    tls_key_path: Path
    kafka_bootstrap_servers: str
    namespace: str = "ads-sandbox"
    tls_ca_bundle: Path | None = None
    bind_host: str = "0.0.0.0"
    port: int = 8080
    startup_seconds: float = 120
    timeout_seconds: float = 120
    ack_seconds: float = 10
    poll_seconds: float = 0.1
    control_seconds: float = 10
    stdout_bytes: int = 65536
    stderr_bytes: int = 65536
    input_bytes: int = 262144
    kafka_security_protocol: str = "PLAINTEXT"
    kafka_sasl_mechanism: str = "PLAIN"
    kafka_sasl_username: str | None = None
    kafka_sasl_password: str | None = field(default=None, repr=False)
    egress: EgressPair | None = None

    def __post_init__(self) -> None:
        for value in (
            self.startup_seconds,
            self.timeout_seconds,
            self.ack_seconds,
            self.poll_seconds,
            self.control_seconds,
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("timeouts must be finite and positive")
        if min(self.stdout_bytes, self.stderr_bytes, self.input_bytes) <= 0:
            raise ValueError("input and output caps must be positive")
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", self.namespace):
            raise ValueError("namespace must be a Kubernetes DNS label")
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

    @property
    def request_topic(self) -> str:
        return f"sandbox.req.{self.sandbox_id}"

    @property
    def reply_topic(self) -> str:
        return f"sandbox.res.{self.sandbox_id}"

    @property
    def group_id(self) -> str:
        return f"ads-sandbox-ipc-{self.sandbox_id}"

    @property
    def selector(self) -> str:
        return f"ads.io/sandbox-id={self.sandbox_id}"


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    if settings.tls_ca_bundle is not None:
        ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
    return context


def load_settings() -> Settings:
    prefix = "ADS_SANDBOX_IPC_"

    def required(name: str) -> str:
        value = os.environ.get(prefix + name, "").strip()
        if not value:
            raise RuntimeError(f"{prefix}{name} is required")
        return value

    ca = os.environ.get(prefix + "TLS_CA_BUNDLE", "").strip()
    settings = Settings(
        sandbox_id=UUID(required("SANDBOX_ID")),
        pid_directory=Path(required("PID_DIRECTORY")),
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
        namespace=os.environ.get(prefix + "NAMESPACE", "ads-sandbox"),
        tls_ca_bundle=Path(ca) if ca else None,
        bind_host=os.environ.get(prefix + "BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get(prefix + "PORT", "8080")),
        startup_seconds=float(os.environ.get(prefix + "STARTUP_SECONDS", "120")),
        timeout_seconds=float(os.environ.get(prefix + "TIMEOUT_SECONDS", "120")),
        ack_seconds=float(os.environ.get(prefix + "ACK_SECONDS", "10")),
        poll_seconds=float(os.environ.get(prefix + "POLL_SECONDS", "0.1")),
        control_seconds=float(os.environ.get(prefix + "CONTROL_SECONDS", "10")),
        stdout_bytes=int(os.environ.get(prefix + "STDOUT_BYTES", "65536")),
        stderr_bytes=int(os.environ.get(prefix + "STDERR_BYTES", "65536")),
        input_bytes=int(os.environ.get(prefix + "INPUT_BYTES", "262144")),
        egress=(
            EgressPair(
                project_id=UUID(required("PROJECT_ID")),
                base_url=required("EGRESS_URL"),
                relay_urls=(required("LOCAL_RELAY_HEALTH_URL"), required("PEER_RELAY_HEALTH_URL")),
                ads_service_subject=UUID(required("ADS_SERVICE_SUBJECT")),
            )
            if any(
                os.environ.get(prefix + key)
                for key in (
                    "PROJECT_ID",
                    "EGRESS_URL",
                    "LOCAL_RELAY_HEALTH_URL",
                    "PEER_RELAY_HEALTH_URL",
                    "ADS_SERVICE_SUBJECT",
                )
            )
            else None
        ),
    )
    load_tls_context(settings)
    return settings
