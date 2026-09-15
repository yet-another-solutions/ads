from __future__ import annotations

import os
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from preference_certs import issue_tls, openssl_available


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _base_env(
    tmp_path: Path,
    *,
    cert: Path,
    key: Path,
    port: int,
    ca: Path | None = None,
) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "ADS_PREFERENCES_KEYCLOAK_WELL_KNOWN_URL": (
                "https://kc/realms/ads/.well-known/openid-configuration"
            ),
            "ADS_PREFERENCES_KEYCLOAK_ISSUER": "https://kc/realms/ads",
            "ADS_PREFERENCES_DATABASE_URL": "sqlite:///:memory:",
            "ADS_PREFERENCES_TLS_CERT_PATH": str(cert),
            "ADS_PREFERENCES_TLS_KEY_PATH": str(key),
            "ADS_PREFERENCES_BIND_HOST": "127.0.0.1",
            "ADS_PREFERENCES_PORT": str(port),
        }
    )
    if ca is None:
        env.pop("ADS_PREFERENCES_TLS_CA_BUNDLE", None)
    else:
        env["ADS_PREFERENCES_TLS_CA_BUNDLE"] = str(ca)
    return env


def _run(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ads_preferences"],
        env=env,
        capture_output=True,
        text=True,
        timeout=8,
    )


def test_uvicorn_exits_on_garbage_tls(tmp_path: Path) -> None:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("not-a-cert")
    key.write_text("not-a-key")
    completed = _run(_base_env(tmp_path, cert=cert, key=key, port=_free_port()))
    assert completed.returncode != 0
    assert "could not be loaded" in completed.stderr + completed.stdout


def test_uvicorn_exits_when_tls_files_missing(tmp_path: Path) -> None:
    completed = _run(
        _base_env(
            tmp_path,
            cert=tmp_path / "missing.crt",
            key=tmp_path / "missing.key",
            port=_free_port(),
        )
    )
    assert completed.returncode != 0
    assert "ADS_PREFERENCES_TLS_CERT_PATH must exist" in completed.stderr + completed.stdout


@pytest.mark.skipif(not openssl_available(), reason="openssl required")
def test_uvicorn_exits_on_garbage_ca_bundle(tmp_path: Path) -> None:
    _, server_crt, server_key = issue_tls(tmp_path)
    garbage = tmp_path / "garbage-ca.crt"
    garbage.write_text("not-a-ca")
    completed = _run(
        _base_env(tmp_path, cert=server_crt, key=server_key, port=_free_port(), ca=garbage)
    )
    assert completed.returncode != 0
    output = completed.stderr + completed.stdout
    assert "ADS_PREFERENCES_TLS_CA_BUNDLE could not be loaded" in output


@pytest.mark.skipif(not openssl_available(), reason="openssl required")
def test_uvicorn_serves_https_health_then_exits(tmp_path: Path) -> None:
    ca_crt, server_crt, server_key = issue_tls(tmp_path)
    port = _free_port()
    log_path = tmp_path / "uvicorn.log"
    with log_path.open("w", encoding="utf-8") as log_file:
        proc = subprocess.Popen(
            [sys.executable, "-m", "ads_preferences"],
            env=_base_env(tmp_path, cert=server_crt, key=server_key, port=port, ca=ca_crt),
            stdout=log_file,
            stderr=log_file,
            text=True,
        )
    try:
        context = ssl.create_default_context(cafile=str(ca_crt))
        for _ in range(80):
            if proc.poll() is not None:
                raise AssertionError(
                    f"uvicorn exited early: {proc.returncode}\n{log_path.read_text()}"
                )
            try:
                with urllib.request.urlopen(
                    f"https://127.0.0.1:{port}/health/live",
                    context=context,
                    timeout=0.3,
                ) as response:
                    if response.status == 200:
                        break
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                time.sleep(0.1)
        else:
            proc.kill()
            raise AssertionError("uvicorn did not serve HTTPS health")
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                raise AssertionError("uvicorn did not die after SIGTERM") from None
    assert proc.returncode is not None
