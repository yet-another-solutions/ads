from __future__ import annotations

import os
import ssl
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ads_sandbox_mcp import __main__ as entrypoint
from ads_sandbox_mcp.config import load_settings, load_tls_context
from sandbox_support import Harness


@pytest.fixture
def certificate(tmp_path: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert, private = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, private


def configured_env(monkeypatch, certificate: tuple[Path, Path]) -> None:
    cert, key = certificate
    for name, value in {
        "DATABASE_URL": "postgresql+psycopg://unused.invalid/database",
        "KEYCLOAK_WELL_KNOWN_URL": "https://unused.invalid/.well-known/openid-configuration",
        "KEYCLOAK_ISSUER": "https://unused.invalid",
        "KEYCLOAK_CLIENT_SECRET": "test-secret-not-logged",
        "KAFKA_BOOTSTRAP_SERVERS": "unused.invalid:9092",
        "TLS_CERT_PATH": str(cert),
        "TLS_KEY_PATH": str(key),
    }.items():
        monkeypatch.setenv("ADS_SANDBOX_MCP_" + name, value)


def test_config_defaults_caps_tls_and_secret_repr(monkeypatch, certificate) -> None:
    configured_env(monkeypatch, certificate)
    settings = load_settings()
    assert settings.timeout_seconds == 120
    assert settings.stdout_bytes == settings.stderr_bytes == 65536
    assert settings.input_bytes == 262144
    assert settings.request_topic == "ads.sandbox.exec.request"
    assert settings.reply_topic == "ads.sandbox.exec.reply"
    assert "test-secret-not-logged" not in repr(settings)
    assert settings.database_url not in repr(settings)
    assert load_tls_context(settings).protocol == ssl.PROTOCOL_TLS_SERVER
    monkeypatch.setenv("ADS_SANDBOX_MCP_TIMEOUT_SECONDS", "10")
    monkeypatch.setenv("ADS_SANDBOX_MCP_INPUT_BYTES", "100")
    monkeypatch.setenv("ADS_SANDBOX_MCP_TLS_CA_BUNDLE", str(certificate[0]))
    monkeypatch.setenv("ADS_SANDBOX_MCP_ALLOWED_HOSTS", "sandbox.example,sandbox.example:*")
    assert load_settings().timeout_seconds == 10
    assert load_settings().input_bytes == 100
    assert load_settings().allowed_hosts == ("sandbox.example", "sandbox.example:*")


@pytest.mark.parametrize(
    "changes",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": -1},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": float("inf")},
        {"stdout_bytes": 0},
        {"stderr_bytes": -1},
        {"input_bytes": 0},
        {"database_url": "sqlite:///bad"},
        {"allowed_hosts": ()},
    ],
)
def test_invalid_settings_fail(harness: Harness, changes: dict) -> None:
    with pytest.raises(ValueError):
        replace(harness.settings, **changes)


@pytest.mark.parametrize("bad", ["TLS_CERT_PATH", "TLS_KEY_PATH", "TLS_CA_BUNDLE"])
def test_tls_failfast_subprocess_before_network(monkeypatch, certificate, tmp_path, bad) -> None:
    configured_env(monkeypatch, certificate)
    invalid = tmp_path / "invalid.pem"
    invalid.write_text("not PEM")
    monkeypatch.setenv("ADS_SANDBOX_MCP_" + bad, str(invalid))
    process = subprocess.run(
        [sys.executable, "-m", "ads_sandbox_mcp"],
        capture_output=True,
        text=True,
        timeout=10,
        env=dict(os.environ),
    )
    assert process.returncode != 0
    assert "ssl.SSLError" in process.stderr
    assert "Started server process" not in process.stderr
    assert "unused.invalid" not in process.stderr
    assert "test-secret-not-logged" not in process.stderr


def test_missing_tls_cannot_enable_http(monkeypatch, certificate) -> None:
    configured_env(monkeypatch, certificate)
    monkeypatch.delenv("ADS_SANDBOX_MCP_TLS_CERT_PATH")
    monkeypatch.setenv("ADS_SANDBOX_MCP_TLS_ENABLED", "false")
    with pytest.raises(RuntimeError, match="TLS_CERT_PATH is required"):
        load_settings()


def test_main_prepares_schema_before_https_server(monkeypatch, certificate) -> None:
    configured_env(monkeypatch, certificate)
    events = []
    app = Mock()
    monkeypatch.setattr(entrypoint, "prepare_schema", lambda **kw: events.append(("schema", kw)))
    monkeypatch.setattr(entrypoint, "create_app", lambda settings: app)
    server = Mock()
    server.run.side_effect = lambda: events.append(("run", None))
    factory = Mock(return_value=server)
    monkeypatch.setattr(entrypoint, "FailFastServer", factory)
    entrypoint.main()
    assert [event for event, _ in events] == ["schema", "run"]
    assert events[0][1]["tables"][0].name == "sandbox_execution"
    config = factory.call_args.args[0]
    assert config.app is app
    assert config.ssl_certfile == str(certificate[0])
    assert config.ssl_keyfile == str(certificate[1])
