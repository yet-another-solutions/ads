from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from unittest.mock import Mock

import pytest
from dishka import Provider, Scope, provide
from litestar.testing import TestClient

from ads_sandbox_ipc import __main__ as entrypoint
from ads_sandbox_ipc.app import create_app
from ads_sandbox_ipc.config import load_settings, load_tls_context
from ads_sandbox_ipc.kafka import KafkaRuntime
from ads_sandbox_ipc.service import IpcService


def test_health_endpoints_have_only_latched_readiness_and_process_liveness(ipc) -> None:
    class FakeRuntime:
        async def start(self):
            pass

        async def stop(self):
            pass

    class Overrides(Provider):
        @provide(scope=Scope.APP, override=True)
        def service(self) -> IpcService:
            return ipc.service

        @provide(scope=Scope.APP, override=True)
        def runtime(self) -> KafkaRuntime:
            return FakeRuntime()

    with TestClient(create_app(ipc.settings, overrides=(Overrides(),))) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 503
        ipc.service.http_ready = True
        ipc.kube.ready = False
        assert client.get("/health/ready").status_code == 200
        assert client.post("/health/live").status_code == 405
        assert client.get("/exec").status_code == 404
        assert not ipc.kube.calls


@pytest.fixture
def tls_settings(ipc, tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    return replace(ipc.settings, tls_cert_path=cert, tls_key_path=key)


def configure(monkeypatch, settings):
    for name, value in {
        "SANDBOX_ID": str(settings.sandbox_id),
        "PID_DIRECTORY": str(settings.pid_directory),
        "KEYCLOAK_WELL_KNOWN_URL": settings.keycloak_well_known_url,
        "KEYCLOAK_ISSUER": settings.keycloak_issuer,
        "KEYCLOAK_CLIENT_SECRET": settings.keycloak_client_secret,
        "KAFKA_BOOTSTRAP_SERVERS": settings.kafka_bootstrap_servers,
        "TLS_CERT_PATH": str(settings.tls_cert_path),
        "TLS_KEY_PATH": str(settings.tls_key_path),
    }.items():
        monkeypatch.setenv("ADS_SANDBOX_IPC_" + name, value)


def test_settings_defaults_and_valid_tls(monkeypatch, tls_settings) -> None:
    configure(monkeypatch, tls_settings)
    settings = load_settings()
    assert settings.timeout_seconds == settings.startup_seconds == 120
    assert settings.ack_seconds == 10
    assert settings.stdout_bytes == settings.stderr_bytes == 65536
    assert settings.input_bytes == 262144
    assert not hasattr(settings, "database_url")
    assert settings.keycloak_client_secret not in repr(settings)
    load_tls_context(replace(settings, tls_ca_bundle=settings.tls_cert_path))


@pytest.mark.parametrize("bad", ["TLS_CERT_PATH", "TLS_KEY_PATH", "TLS_CA_BUNDLE"])
def test_tls_failure_exits_before_network(monkeypatch, tls_settings, tmp_path, bad) -> None:
    configure(monkeypatch, tls_settings)
    invalid = tmp_path / "bad.pem"
    invalid.write_text("not PEM")
    monkeypatch.setenv("ADS_SANDBOX_IPC_" + bad, str(invalid))
    process = subprocess.run(
        [sys.executable, "-m", "ads_sandbox_ipc"],
        env=dict(os.environ),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert process.returncode != 0
    assert "ssl.SSLError" in process.stderr
    assert "Started server process" not in process.stderr
    assert tls_settings.keycloak_client_secret not in process.stderr


def test_main_always_passes_tls_and_has_no_schema_bootstrap(monkeypatch, tls_settings) -> None:
    monkeypatch.setattr(entrypoint, "load_settings", Mock(return_value=tls_settings))
    app = Mock()
    monkeypatch.setattr(entrypoint, "create_app", Mock(return_value=app))
    server = Mock()
    factory = Mock(return_value=server)
    monkeypatch.setattr(entrypoint, "FailFastServer", factory)
    entrypoint.main()
    config = factory.call_args.args[0]
    assert config.ssl_certfile == str(tls_settings.tls_cert_path)
    assert config.ssl_keyfile == str(tls_settings.tls_key_path)
    assert config.app is app
    server.run.assert_called_once()
