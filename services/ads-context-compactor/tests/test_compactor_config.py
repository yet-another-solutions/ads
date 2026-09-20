import os
import subprocess
import sys
from pathlib import Path

import pytest

from ads_context_compactor.config import Settings, load_settings


def settings(**extra):
    return Settings(
        "https://identity.test/discovery",
        "https://identity.test",
        "fixture-secret",
        Path("missing-cert"),
        Path("missing-key"),
        **extra,
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"reserve": 0},
        {"summary_cap": -1},
        {"port": 65536},
        {"meter_url": "http://meter.test/meter"},
        {"meter_url": "https://user:secret@meter.test/meter"},
    ],
)
def test_invalid_runtime_settings_fail_closed(extra):
    with pytest.raises(ValueError):
        settings(**extra)


def test_client_identity_is_independent_of_resource_audience(monkeypatch):
    values = {
        "KEYCLOAK_WELL_KNOWN_URL": "https://identity.test/discovery",
        "KEYCLOAK_ISSUER": "https://identity.test",
        "KEYCLOAK_CLIENT_SECRET": "fixture-secret",
        "KEYCLOAK_CLIENT_ID": "compactor-client",
        "KEYCLOAK_AUDIENCE": "compactor-resource",
        "TLS_CERT_PATH": "unused",
        "TLS_KEY_PATH": "unused",
    }
    for key, value in values.items():
        monkeypatch.setenv("ADS_CONTEXT_COMPACTOR_" + key, value)
    monkeypatch.setattr("ads_context_compactor.config.load_tls_context", lambda settings: None)
    loaded = load_settings()
    assert loaded.keycloak_client_id == "compactor-client"
    assert loaded.keycloak_audience == "compactor-resource"


def test_missing_tls_fails_before_server_start(tmp_path):
    env = dict(os.environ)
    for key, value in {
        "KEYCLOAK_WELL_KNOWN_URL": "https://identity.test/discovery",
        "KEYCLOAK_ISSUER": "https://identity.test",
        "KEYCLOAK_CLIENT_SECRET": "fixture-secret",
        "TLS_CERT_PATH": str(tmp_path / "absent.pem"),
        "TLS_KEY_PATH": str(tmp_path / "absent.key"),
    }.items():
        env["ADS_CONTEXT_COMPACTOR_" + key] = value
    result = subprocess.run(
        [sys.executable, "-m", "ads_context_compactor"],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode != 0
    assert "FileNotFoundError" in result.stderr
    assert "Uvicorn running" not in result.stderr
    assert "fixture-secret" not in result.stderr
