from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    api_token: str
    tls_cert_path: Path
    tls_key_path: Path
    amqp_url: str = ""
    database_url: str = ""
    tls_ca_bundle: Path | None = None
    bind_host: str = "0.0.0.0"
    port: int = 8080
    prefetch: int = 100
    nack_pause_seconds: float = 1.0
    partitions_ahead: int = 2
    partition_check_seconds: float = 86400.0
    deny_repeat_multiplier: int = 3


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


def _seconds(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a whole number") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be greater than zero")
    return value


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    except ssl.SSLError as exc:
        raise RuntimeError("ADS audit TLS certificate and key could not be loaded") from exc
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
    api_token = _env("ADS_AUDIT_API_TOKEN")
    if len(api_token.strip()) < 16:
        raise RuntimeError("ADS_AUDIT_API_TOKEN must be at least 16 characters")
    amqp_url = _env("ADS_AMQP_URL").strip()
    if not amqp_url:
        raise RuntimeError("ADS_AMQP_URL is required")
    database_url = _env("ADS_DATABASE_URL").strip()
    if not database_url:
        raise RuntimeError("ADS_DATABASE_URL is required")
    settings = Settings(
        api_token=api_token,
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        amqp_url=amqp_url,
        database_url=database_url,
        tls_ca_bundle=_existing_file("ADS_TLS_CA_BUNDLE", ca_raw) if ca_raw else None,
        bind_host=_env("ADS_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_PORT", "8080")),
        prefetch=_seconds("ADS_AUDIT_PREFETCH", 100),
        partitions_ahead=_seconds("ADS_AUDIT_PARTITIONS_AHEAD", 2),
    )
    load_tls_context(settings)
    return settings
