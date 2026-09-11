from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"{name} is required")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    keycloak_well_known_url: str
    keycloak_issuer: str
    keycloak_client_id: str
    keycloak_client_secret: str
    keycloak_audience: str
    keycloak_role: str
    session_secret: str
    public_base_url: str
    data_dir: Path
    tls_enabled: bool
    tls_cert_path: Path | None
    tls_key_path: Path | None
    bind_host: str
    port: int

    def session_secret_bytes(self) -> bytes:
        if not self.session_secret.strip():
            raise RuntimeError("ADS_SESSION_SECRET must be non-empty")
        encoded = self.session_secret.encode("utf-8")
        if len(encoded) < 16:
            raise RuntimeError("ADS_SESSION_SECRET must be at least 16 bytes")
        return encoded[:32].ljust(32, b"\0")


def load_settings() -> Settings:
    tls_enabled = _env_bool("ADS_TLS_ENABLED", default=False)
    cert_raw = os.environ.get("ADS_TLS_CERT_PATH", "").strip()
    key_raw = os.environ.get("ADS_TLS_KEY_PATH", "").strip()
    if tls_enabled and (not cert_raw or not key_raw):
        raise RuntimeError(
            "ADS_TLS_CERT_PATH and ADS_TLS_KEY_PATH are required when TLS is enabled"
        )
    session_secret = _env("ADS_SESSION_SECRET")
    if not session_secret.strip():
        raise RuntimeError("ADS_SESSION_SECRET must be non-empty")
    return Settings(
        keycloak_well_known_url=_env("ADS_KEYCLOAK_WELL_KNOWN_URL"),
        keycloak_issuer=_env("ADS_KEYCLOAK_ISSUER"),
        keycloak_client_id=_env("ADS_KEYCLOAK_CLIENT_ID"),
        keycloak_client_secret=_env("ADS_KEYCLOAK_CLIENT_SECRET"),
        keycloak_audience=_env("ADS_KEYCLOAK_AUDIENCE", "ads"),
        keycloak_role=_env("ADS_KEYCLOAK_ROLE", "user"),
        session_secret=session_secret,
        public_base_url=_env("ADS_PUBLIC_BASE_URL").rstrip("/"),
        data_dir=Path(_env("ADS_DATA_DIR", "/data")),
        tls_enabled=tls_enabled,
        tls_cert_path=Path(cert_raw) if cert_raw else None,
        tls_key_path=Path(key_raw) if key_raw else None,
        bind_host=_env("ADS_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_PORT", "8080")),
    )
