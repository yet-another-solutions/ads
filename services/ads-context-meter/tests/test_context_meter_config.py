import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize("material", ["missing", "garbage"])
def test_tls_failure_exits_before_worker_or_listener(tmp_path, material):
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    if material == "garbage":
        cert.write_text("garbage")
        key.write_text("garbage")
    env = {
        **os.environ,
        "ADS_CONTEXT_METER_TLS_CERT_PATH": str(cert),
        "ADS_CONTEXT_METER_TLS_KEY_PATH": str(key),
        "ADS_CONTEXT_METER_KEYCLOAK_WELL_KNOWN_URL": "https://unused",
        "ADS_CONTEXT_METER_KEYCLOAK_ISSUER": "https://unused",
    }
    result = subprocess.run(
        [sys.executable, "-m", "ads_context_meter"],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0
    assert "BrokenProcessPool" not in result.stderr
    assert "Uvicorn running" not in result.stderr
    expected = "must exist" if material == "missing" else "could not be loaded"
    assert expected in result.stderr
