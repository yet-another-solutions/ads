from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from pathlib import Path


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


@dataclass(frozen=True, slots=True)
class Settings:
    keycloak_well_known_url: str
    keycloak_issuer: str
    keycloak_audience: str
    keycloak_client_id: str
    tokenizer_directory: Path
    tls_cert_path: Path
    tls_key_path: Path
    tls_ca_bundle: Path | None
    bind_host: str
    port: int


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    except ssl.SSLError as exc:
        raise RuntimeError("ADS context meter TLS certificate and key could not be loaded") from exc
    if settings.tls_ca_bundle is not None:
        try:
            ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        except ssl.SSLError as exc:
            raise RuntimeError("ADS_CONTEXT_METER_TLS_CA_BUNDLE could not be loaded") from exc
    return context


def load_settings() -> Settings:
    cert_path = _existing_file(
        "ADS_CONTEXT_METER_TLS_CERT_PATH",
        _env("ADS_CONTEXT_METER_TLS_CERT_PATH").strip(),
    )
    key_path = _existing_file(
        "ADS_CONTEXT_METER_TLS_KEY_PATH",
        _env("ADS_CONTEXT_METER_TLS_KEY_PATH").strip(),
    )
    ca_raw = os.environ.get("ADS_CONTEXT_METER_TLS_CA_BUNDLE", "").strip()
    ca_bundle = _existing_file("ADS_CONTEXT_METER_TLS_CA_BUNDLE", ca_raw) if ca_raw else None
    settings = Settings(
        keycloak_well_known_url=_env("ADS_CONTEXT_METER_KEYCLOAK_WELL_KNOWN_URL"),
        keycloak_issuer=_env("ADS_CONTEXT_METER_KEYCLOAK_ISSUER"),
        keycloak_audience=_env("ADS_CONTEXT_METER_KEYCLOAK_AUDIENCE", "ads-context-meter"),
        keycloak_client_id="ads-engine",
        tokenizer_directory=Path(_env("ADS_CONTEXT_METER_TOKENIZER_DIRECTORY", "/opt/tokenizers")),
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        tls_ca_bundle=ca_bundle,
        bind_host=_env("ADS_CONTEXT_METER_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_CONTEXT_METER_PORT", "8080")),
    )
    load_tls_context(settings)
    return settings
