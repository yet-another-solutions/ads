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
class SessionSettings:
    """Helm-owned object inputs. Only references, never inline credentials."""

    guest_image: str
    ipc_image: str
    ipc_storage_class: str
    ipc_service_account: str
    ipc_config_map: str
    ipc_secret: str
    ipc_tls_secret: str
    ipc_node_selector: dict[str, str]
    ipc_ca_secret: str | None = None
    ipc_size: str = "1Gi"
    guest_resources: dict[str, Any] = field(default_factory=dict)
    ipc_resources: dict[str, Any] = field(default_factory=dict)
    ipc_tolerations: list[dict[str, Any]] = field(default_factory=list)
    create_seconds: float = 120

    def __post_init__(self) -> None:
        for name in (
            self.ipc_storage_class,
            self.ipc_service_account,
            self.ipc_config_map,
            self.ipc_secret,
            self.ipc_tls_secret,
            self.ipc_ca_secret,
        ):
            if name is not None and (
                len(name) > 253 or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", name)
            ):
                raise ValueError("session object references must be DNS-safe names")
        if not self.guest_image.strip() or not self.ipc_image.strip():
            raise ValueError("guest and IPC images are required")
        if self.ipc_storage_class == "sandbox-block":
            raise ValueError("IPC requires an application Filesystem storage class")
        size_bytes(self.ipc_size)
        if not math.isfinite(self.create_seconds) or self.create_seconds <= 0:
            raise ValueError("session create timeout must be finite and positive")
        if (
            not isinstance(self.ipc_node_selector, dict)
            or not self.ipc_node_selector
            or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in self.ipc_node_selector.items()
            )
        ):
            raise ValueError("IPC application node selector must be a non-empty string map")
        if not all(isinstance(r, dict) for r in (self.guest_resources, self.ipc_resources)):
            raise ValueError("session resources must be JSON objects")
        if not isinstance(self.ipc_tolerations, list) or not all(
            isinstance(t, dict) for t in self.ipc_tolerations
        ):
            raise ValueError("IPC tolerations must be a JSON array of objects")


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
    session_objects: SessionSettings | None = None
    keycloak_issuer: str = ""
    keycloak_well_known_url: str = ""
    keycloak_client_secret: str = field(default="", repr=False)
    ready_seconds: float = 120
    barrier_seconds: float = 3
    topic_replication_factor: int = 1
    idle_seconds: float = 1800
    detached_seconds: float = 7200
    cleanup_seconds: float = 120
    pvc_timeout_seconds: float = 120
    lifecycle_batch: int = 50
    ping_interval_seconds: float = 10
    ping_timeout_seconds: float = 30
    recovery_seconds: float = 600

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
        for value in (
            self.poll_seconds,
            self.control_seconds,
            self.node_fresh_seconds,
            self.ready_seconds,
            self.barrier_seconds,
            self.idle_seconds,
            self.detached_seconds,
            self.cleanup_seconds,
            self.pvc_timeout_seconds,
            self.ping_interval_seconds,
            self.ping_timeout_seconds,
            self.recovery_seconds,
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("poll and timeout settings must be finite and positive")
        if self.ping_timeout_seconds <= self.ping_interval_seconds:
            raise ValueError("ping timeout must exceed its interval")
        if self.recovery_seconds <= self.cleanup_seconds:
            raise ValueError("recovery timeout must exceed cleanup timeout")
        if self.bake_seconds <= 0:
            raise ValueError("bake timeout must be positive")
        if self.topic_replication_factor < 1:
            raise ValueError("topic replication factor must be positive")
        if self.lifecycle_batch < 1:
            raise ValueError("lifecycle batch must be positive")
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
        session_objects=(
            SessionSettings(**json.loads(os.environ[prefix + "SESSION_OBJECTS"]))
            if os.environ.get(prefix + "SESSION_OBJECTS", "").strip()
            else None
        ),
        keycloak_issuer=os.environ.get(prefix + "KEYCLOAK_ISSUER", ""),
        keycloak_well_known_url=os.environ.get(prefix + "KEYCLOAK_WELL_KNOWN_URL", ""),
        keycloak_client_secret=os.environ.get(prefix + "KEYCLOAK_CLIENT_SECRET", ""),
        ready_seconds=float(os.environ.get(prefix + "READY_SECONDS", "120")),
        barrier_seconds=float(os.environ.get(prefix + "BARRIER_SECONDS", "3")),
        topic_replication_factor=int(os.environ.get(prefix + "TOPIC_REPLICATION_FACTOR", "1")),
        idle_seconds=float(os.environ.get(prefix + "IDLE_SECONDS", "1800")),
        detached_seconds=float(os.environ.get(prefix + "DETACHED_SECONDS", "7200")),
        cleanup_seconds=float(os.environ.get(prefix + "CLEANUP_SECONDS", "120")),
        pvc_timeout_seconds=float(os.environ.get(prefix + "PVC_TIMEOUT_SECONDS", "120")),
        lifecycle_batch=int(os.environ.get(prefix + "LIFECYCLE_BATCH", "50")),
        ping_interval_seconds=float(os.environ.get(prefix + "PING_INTERVAL_SECONDS", "10")),
        ping_timeout_seconds=float(os.environ.get(prefix + "PING_TIMEOUT_SECONDS", "30")),
        recovery_seconds=float(os.environ.get(prefix + "RECOVERY_SECONDS", "600")),
    )
    load_tls_context(settings)
    if settings.session_objects is None:
        raise RuntimeError("ADS_SANDBOX_MANAGER_SESSION_OBJECTS is required")
    if not settings.keycloak_client_secret or not all(
        value.startswith("https://")
        for value in (settings.keycloak_issuer, settings.keycloak_well_known_url)
    ):
        raise RuntimeError("manager Keycloak HTTPS issuer, discovery and client secret required")
    return settings
