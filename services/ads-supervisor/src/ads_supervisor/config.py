from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from pathlib import Path

from ads_policy.contract import Placement


@dataclass(frozen=True, slots=True)
class Settings:
    """Every tunable of the supervisor. Modules read them, never redefine them."""

    api_token: str
    tls_cert_path: Path
    tls_key_path: Path
    subject: str
    project: str
    repo: str
    env: str
    policy_url: str = ""
    policy_api_token: str = ""
    amqp_url: str = ""
    workdir: str = "/workspace"
    placement: Placement = Placement.CLUSTER
    runtime_class_name: str | None = None
    node_labels: dict[str, str] | None = None
    attributes: dict[str, str] | None = None
    tls_ca_bundle: Path | None = None
    bind_host: str = "0.0.0.0"
    port: int = 8080
    audit_flush_seconds: float = 1.0


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"{name} is required")
    return value


def _required(name: str) -> str:
    value = _env(name).strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _existing_file(name: str, raw: str) -> Path:
    path = Path(raw)
    if not path.is_file():
        raise RuntimeError(f"{name} must exist")
    return path


def _pairs(name: str) -> dict[str, str]:
    """``key=value,key=value`` — how a controller hands over what it read off the pod."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return {}
    pairs: dict[str, str] = {}
    for item in raw.split(","):
        key, _, value = item.partition("=")
        if key.strip():
            pairs[key.strip()] = value.strip()
    return pairs


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    except ssl.SSLError as exc:
        raise RuntimeError("ADS supervisor TLS certificate and key could not be loaded") from exc
    if settings.tls_ca_bundle is not None:
        try:
            ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        except ssl.SSLError as exc:
            raise RuntimeError("ADS_TLS_CA_BUNDLE could not be loaded") from exc
    return context


def load_settings() -> Settings:
    cert_path = _existing_file("ADS_TLS_CERT_PATH", _required("ADS_TLS_CERT_PATH"))
    key_path = _existing_file("ADS_TLS_KEY_PATH", _required("ADS_TLS_KEY_PATH"))
    ca_raw = os.environ.get("ADS_TLS_CA_BUNDLE", "").strip()
    api_token = _required("ADS_SUPERVISOR_API_TOKEN")
    if len(api_token) < 16:
        raise RuntimeError("ADS_SUPERVISOR_API_TOKEN must be at least 16 characters")
    raw_placement = os.environ.get("ADS_PLACEMENT", Placement.CLUSTER.value).strip()
    try:
        placement = Placement(raw_placement)
    except ValueError as exc:
        raise RuntimeError(f"ADS_PLACEMENT must be one of {[p.value for p in Placement]}") from exc
    runtime_class = os.environ.get("ADS_RUNTIME_CLASS_NAME", "").strip()
    settings = Settings(
        api_token=api_token,
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        subject=_required("ADS_SUBJECT"),
        project=_required("ADS_PROJECT"),
        repo=_required("ADS_REPO"),
        env=_env("ADS_ENV", "dev"),
        policy_url=_required("ADS_POLICY_URL").rstrip("/"),
        policy_api_token=_required("ADS_POLICY_API_TOKEN"),
        amqp_url=_required("ADS_AMQP_URL"),
        workdir=_env("ADS_RUN_WORKDIR", "/workspace").rstrip("/") or "/",
        placement=placement,
        runtime_class_name=runtime_class or None,
        node_labels=_pairs("ADS_NODE_LABELS"),
        attributes=_pairs("ADS_ATTRIBUTES"),
        tls_ca_bundle=_existing_file("ADS_TLS_CA_BUNDLE", ca_raw) if ca_raw else None,
        bind_host=_env("ADS_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_PORT", "8080")),
    )
    load_tls_context(settings)
    return settings
