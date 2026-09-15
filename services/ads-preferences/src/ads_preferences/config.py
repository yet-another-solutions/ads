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
    allowed_callers: frozenset[str]
    database_url: str
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
        raise RuntimeError("ADS preferences TLS certificate and key could not be loaded") from exc
    if settings.tls_ca_bundle is not None:
        try:
            ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        except ssl.SSLError as exc:
            raise RuntimeError("ADS_PREFERENCES_TLS_CA_BUNDLE could not be loaded") from exc
    return context


def load_settings() -> Settings:
    cert_path = _existing_file(
        "ADS_PREFERENCES_TLS_CERT_PATH",
        _env("ADS_PREFERENCES_TLS_CERT_PATH").strip(),
    )
    key_path = _existing_file(
        "ADS_PREFERENCES_TLS_KEY_PATH",
        _env("ADS_PREFERENCES_TLS_KEY_PATH").strip(),
    )
    ca_raw = os.environ.get("ADS_PREFERENCES_TLS_CA_BUNDLE", "").strip()
    ca_bundle = _existing_file("ADS_PREFERENCES_TLS_CA_BUNDLE", ca_raw) if ca_raw else None
    allowed_raw = os.environ.get("ADS_PREFERENCES_ALLOWED_CALLERS", "ads")
    callers = frozenset(part.strip() for part in allowed_raw.split(",") if part.strip())
    if not callers:
        raise RuntimeError("ADS_PREFERENCES_ALLOWED_CALLERS is required")
    settings = Settings(
        keycloak_well_known_url=_env("ADS_PREFERENCES_KEYCLOAK_WELL_KNOWN_URL"),
        keycloak_issuer=_env("ADS_PREFERENCES_KEYCLOAK_ISSUER"),
        keycloak_audience=_env("ADS_PREFERENCES_KEYCLOAK_AUDIENCE", "ads-preferences"),
        keycloak_client_id=_env("ADS_PREFERENCES_KEYCLOAK_CLIENT_ID", "ads"),
        allowed_callers=callers,
        database_url=_env("ADS_PREFERENCES_DATABASE_URL"),
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        tls_ca_bundle=ca_bundle,
        bind_host=_env("ADS_PREFERENCES_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_PREFERENCES_PORT", "8080")),
    )
    load_tls_context(settings)
    return settings
