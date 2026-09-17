from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MIN_API_TOKEN_LENGTH = 16


@dataclass(frozen=True, slots=True)
class Settings:
    api_token: str
    tls_cert_path: Path
    tls_key_path: Path
    model_dir: Path
    injection_threshold: float = 0.5
    window_tokens: int = 512
    window_overlap_tokens: int = 64
    malicious_label_index: int = 1
    max_texts_per_scan: int = 256
    max_characters_per_scan: int = 1_000_000
    bind_host: str = "0.0.0.0"
    port: int = 8080


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _existing_file(name: str) -> Path:
    path = Path(_required(name))
    if not path.is_file():
        raise RuntimeError(f"{name} must exist")
    return path


def _probability(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number") from exc
    if not 0.0 < value < 1.0:
        raise RuntimeError(f"{name} must be between 0 and 1")
    return value


def _positive(name: str, default: int) -> int:
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


def load_settings() -> Settings:
    api_token = _required("ADS_SCANNER_API_TOKEN")
    if len(api_token) < MIN_API_TOKEN_LENGTH:
        raise RuntimeError(
            f"ADS_SCANNER_API_TOKEN must be at least {MIN_API_TOKEN_LENGTH} characters"
        )
    model_dir = Path(_required("ADS_SCANNER_MODEL_DIR"))
    if not model_dir.is_dir():
        raise RuntimeError("ADS_SCANNER_MODEL_DIR must be a directory")
    return Settings(
        api_token=api_token,
        tls_cert_path=_existing_file("ADS_TLS_CERT_PATH"),
        tls_key_path=_existing_file("ADS_TLS_KEY_PATH"),
        model_dir=model_dir,
        injection_threshold=_probability("ADS_SCANNER_THRESHOLD", 0.5),
        window_tokens=_positive("ADS_SCANNER_WINDOW_TOKENS", 512),
        window_overlap_tokens=_positive("ADS_SCANNER_WINDOW_OVERLAP_TOKENS", 64),
        bind_host=os.environ.get("ADS_BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get("ADS_PORT", "8080")),
    )
