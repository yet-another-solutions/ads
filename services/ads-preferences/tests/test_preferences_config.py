from __future__ import annotations

from pathlib import Path

import pytest

from ads_preferences.config import load_settings


def test_missing_tls_files_fail_fast(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(
        "ADS_PREFERENCES_KEYCLOAK_WELL_KNOWN_URL",
        "https://kc/realms/ads/.well-known/openid-configuration",
    )
    monkeypatch.setenv("ADS_PREFERENCES_KEYCLOAK_ISSUER", "https://kc/realms/ads")
    monkeypatch.setenv("ADS_PREFERENCES_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("ADS_PREFERENCES_TLS_CERT_PATH", str(tmp_path / "missing.crt"))
    monkeypatch.setenv("ADS_PREFERENCES_TLS_KEY_PATH", str(tmp_path / "missing.key"))
    with pytest.raises(RuntimeError, match="ADS_PREFERENCES_TLS_CERT_PATH must exist"):
        load_settings()
