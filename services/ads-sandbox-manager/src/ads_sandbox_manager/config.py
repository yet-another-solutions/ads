from __future__ import annotations

import json
import math
import os
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def size_bytes(value: str) -> int:
    """The integer quantity grammar accepted by the golden entrypoint."""
    match = re.fullmatch(r"([0-9]+)(Ki|Mi|Gi|Ti|Pi|k|M|G|T|P)?", value)
    if match is None:
        raise ValueError("size must be a positive integer Kubernetes storage quantity")
    suffix = match[2] or ""
    factors = {"": 1}
    factors.update({s + "i": 1024**i for i, s in enumerate("KMGTP", 1)})
    factors.update({s: 1000**i for i, s in enumerate("kMGTP", 1)})
    result = int(match[1]) * factors[suffix]
    if not 0 < result < 2**63:
        raise ValueError("size must fit a positive signed 64-bit byte count")
    return result


@dataclass(frozen=True, slots=True)
class Settings:
    golden_version: str
    golden_image: str
    session_size: str
    database_url: str = field(repr=False)
    kafka_bootstrap_servers: str
    tls_cert_path: Path
    tls_key_path: Path
    namespace: str = "ads-sandbox"
    golden_slack: str = "2Gi"
    node_selector: dict[str, str] = field(default_factory=lambda: {"ads.io/sandbox-node": "true"})
    tolerations: list[dict[str, Any]] = field(default_factory=list)
    image_pull_secrets: tuple[str, ...] = ()
    resources: dict[str, Any] = field(default_factory=dict)
    poll_seconds: float = 10
    control_seconds: float = 10
    bake_seconds: int = 1800
    node_fresh_seconds: float = 600
    tls_ca_bundle: Path | None = None
    bind_host: str = "0.0.0.0"
    port: int = 8080
    kafka_security_protocol: str = "PLAINTEXT"
    kafka_sasl_mechanism: str = "SCRAM-SHA-512"
    kafka_sasl_username: str | None = None
    kafka_sasl_password: str | None = field(default=None, repr=False)
    kafka_ca_bundle: Path | None = None

    def __post_init__(self) -> None:
        if (
            not re.fullmatch(
                r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?", self.golden_version
            )
            or len(self.golden_name) > 63
        ):
            raise ValueError("golden version must be a DNS-safe ADS release version")
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", self.namespace):
            raise ValueError("namespace must be a Kubernetes DNS label")
        if not self.golden_image.strip():
            raise ValueError("golden image is required")
        if not self.database_url.startswith("postgresql+psycopg://"):
            raise ValueError("manager requires PostgreSQL with psycopg")
        if size_bytes(self.golden_slack) < 2 * 1024**3:
            raise ValueError("golden slack must be at least 2Gi")
        if self.golden_bytes >= 2**63:
            raise ValueError("golden size exceeds signed 64-bit bytes")
        for value in (self.poll_seconds, self.control_seconds, self.node_fresh_seconds):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("poll and timeout settings must be finite and positive")
        if self.bake_seconds <= 0:
            raise ValueError("bake timeout must be positive")
        if (
            not isinstance(self.node_selector, dict)
            or not self.node_selector
            or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in self.node_selector.items()
            )
        ):
            raise ValueError("sandbox node selector must be a non-empty string map")
        if not isinstance(self.tolerations, list) or not all(
            isinstance(t, dict) for t in self.tolerations
        ):
            raise ValueError("tolerations must be a JSON array of objects")
        if not isinstance(self.resources, dict):
            raise ValueError("resources must be a JSON object")
        if self.kafka_security_protocol not in ("PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL"):
            raise ValueError("unsupported Kafka security protocol")
        if self.kafka_security_protocol.startswith("SASL") and not (
            self.kafka_sasl_username and self.kafka_sasl_password
        ):
            raise ValueError("Kafka SASL username and password are required")

    @property
    def golden_name(self) -> str:
        return "ads-sandbox-golden-" + self.golden_version.replace(".", "-")

    @property
    def golden_bytes(self) -> int:
        return size_bytes(self.session_size) + size_bytes(self.golden_slack)


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    if settings.tls_ca_bundle:
        ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
    return context


def load_settings() -> Settings:
    prefix = "ADS_SANDBOX_MANAGER_"

    def required(name: str) -> str:
        value = os.environ.get(prefix + name, "").strip()
        if not value:
            raise RuntimeError(f"{prefix}{name} is required")
        return value

    def optional_path(name: str) -> Path | None:
        value = os.environ.get(prefix + name, "").strip()
        return Path(value) if value else None

    session_size = os.environ.get("ADS_SESSION_SIZE", "").strip()
    if not session_size:
        raise RuntimeError("ADS_SESSION_SIZE is required from the published release")
    settings = Settings(
        golden_version=required("GOLDEN_VERSION"),
        golden_image=required("GOLDEN_IMAGE"),
        session_size=session_size,
        database_url=required("DATABASE_URL"),
        kafka_bootstrap_servers=required("KAFKA_BOOTSTRAP_SERVERS"),
        tls_cert_path=Path(required("TLS_CERT_PATH")),
        tls_key_path=Path(required("TLS_KEY_PATH")),
        namespace=os.environ.get(prefix + "NAMESPACE", "ads-sandbox"),
        golden_slack=os.environ.get(prefix + "GOLDEN_SLACK", "2Gi"),
        node_selector=json.loads(
            os.environ.get(prefix + "NODE_SELECTOR", '{"ads.io/sandbox-node":"true"}')
        ),
        tolerations=json.loads(os.environ.get(prefix + "TOLERATIONS", "[]")),
        resources=json.loads(os.environ.get(prefix + "RESOURCES", "{}")),
        image_pull_secrets=tuple(
            s.strip()
            for s in os.environ.get(prefix + "IMAGE_PULL_SECRETS", "").split(",")
            if s.strip()
        ),
        poll_seconds=float(os.environ.get(prefix + "POLL_SECONDS", "10")),
        control_seconds=float(os.environ.get(prefix + "CONTROL_SECONDS", "10")),
        bake_seconds=int(os.environ.get(prefix + "BAKE_SECONDS", "1800")),
        node_fresh_seconds=float(os.environ.get(prefix + "NODE_FRESH_SECONDS", "600")),
        tls_ca_bundle=optional_path("TLS_CA_BUNDLE"),
        bind_host=os.environ.get(prefix + "BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get(prefix + "PORT", "8080")),
        kafka_security_protocol=os.environ.get(prefix + "KAFKA_SECURITY_PROTOCOL", "PLAINTEXT"),
        kafka_sasl_mechanism=os.environ.get(prefix + "KAFKA_SASL_MECHANISM", "SCRAM-SHA-512"),
        kafka_sasl_username=os.environ.get(prefix + "KAFKA_SASL_USERNAME"),
        kafka_sasl_password=os.environ.get(prefix + "KAFKA_SASL_PASSWORD"),
        kafka_ca_bundle=optional_path("KAFKA_CA_BUNDLE"),
    )
    load_tls_context(settings)
    return settings
