from __future__ import annotations

import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx2
import pytest

from tests.certs import issue_tls, openssl_available


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
    keycloak_well_known_url: str = "https://kc/realms/ads/.well-known/openid-configuration",
) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "ADS_KEYCLOAK_WELL_KNOWN_URL": keycloak_well_known_url,
            "ADS_KEYCLOAK_ISSUER": "https://kc/realms/ads",
            "ADS_KEYCLOAK_CLIENT_ID": "ads",
            "ADS_KEYCLOAK_CLIENT_SECRET": "secret",
            "ADS_SESSION_SECRET": "test-session-secret-32b!",
            "ADS_PUBLIC_BASE_URL": f"https://127.0.0.1:{port}",
            "ADS_TLS_CERT_PATH": str(cert),
            "ADS_TLS_KEY_PATH": str(key),
            "ADS_BIND_HOST": "127.0.0.1",
            "ADS_PORT": str(port),
            "ADS_DATABASE_URL": f"sqlite:///{tmp_path / 'ads.db'}",
            "ADS_KAFKA_BOOTSTRAP_SERVERS": "",
            "ADS_PREFERENCES_BASE_URL": "https://ads-preferences.invalid",
        }
    )
    if ca is None:
        env.pop("ADS_TLS_CA_BUNDLE", None)
    else:
        env["ADS_TLS_CA_BUNDLE"] = str(ca)
    return env


@pytest.fixture
def keycloak_well_known_url() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            origin = f"http://127.0.0.1:{self.server.server_port}"
            body = (f'{{"jwks_uri":"{origin}/certs","token_endpoint":"{origin}/token"}}').encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/.well-known/openid-configuration"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run_ads(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ads"],
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
    completed = _run_ads(_base_env(tmp_path, cert=cert, key=key, port=_free_port()))
    assert completed.returncode != 0
    assert "could not be loaded" in completed.stderr + completed.stdout


def test_uvicorn_exits_when_tls_files_missing(tmp_path: Path) -> None:
    completed = _run_ads(
        _base_env(
            tmp_path,
            cert=tmp_path / "missing.crt",
            key=tmp_path / "missing.key",
            port=_free_port(),
        )
    )
    assert completed.returncode != 0
    assert "ADS_TLS_CERT_PATH must exist" in completed.stderr + completed.stdout


@pytest.mark.skipif(not openssl_available(), reason="openssl required")
def test_uvicorn_exits_on_garbage_ca_bundle(tmp_path: Path) -> None:
    _, server_crt, server_key = issue_tls(tmp_path)
    garbage = tmp_path / "garbage-ca.crt"
    garbage.write_text("not-a-ca")
    completed = _run_ads(
        _base_env(tmp_path, cert=server_crt, key=server_key, port=_free_port(), ca=garbage)
    )
    assert completed.returncode != 0
    assert "ADS_TLS_CA_BUNDLE could not be loaded" in completed.stderr + completed.stdout


@pytest.mark.skipif(not openssl_available(), reason="openssl required")
def test_uvicorn_serves_https_health_then_exits(
    tmp_path: Path,
    keycloak_well_known_url: str,
) -> None:
    ca_crt, server_crt, server_key = issue_tls(tmp_path)
    port = _free_port()
    log_path = tmp_path / "uvicorn.log"
    with log_path.open("w", encoding="utf-8") as log_file:
        proc = subprocess.Popen(
            [sys.executable, "-m", "ads"],
            env=_base_env(
                tmp_path,
                cert=server_crt,
                key=server_key,
                port=port,
                ca=ca_crt,
                keycloak_well_known_url=keycloak_well_known_url,
            ),
            stdout=log_file,
            stderr=log_file,
            text=True,
        )
    try:
        for _ in range(80):
            if proc.poll() is not None:
                raise AssertionError(
                    f"uvicorn exited early: {proc.returncode}\n{log_path.read_text()}"
                )
            try:
                response = httpx2.get(
                    f"https://127.0.0.1:{port}/health/live",
                    verify=ssl.create_default_context(cafile=str(ca_crt)),
                    timeout=0.3,
                )
                if response.status_code == 200:
                    break
            except httpx2.HTTPError:
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
