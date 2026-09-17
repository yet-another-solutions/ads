from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    tls_cert_path: Path
    tls_key_path: Path
    bind_host: str = "0.0.0.0"
    port: int = 8080


def _existing_file(name: str) -> Path:
    raw = os.environ.get(name, "").strip()
    if not raw:
        raise RuntimeError(f"{name} is required")
    path = Path(raw)
    if not path.is_file():
        raise RuntimeError(f"{name} must exist")
    return path


def load_settings() -> Settings:
    return Settings(
        tls_cert_path=_existing_file("ADS_TLS_CERT_PATH"),
        tls_key_path=_existing_file("ADS_TLS_KEY_PATH"),
        bind_host=os.environ.get("ADS_BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get("ADS_PORT", "8080")),
    )
