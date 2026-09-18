from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from unittest.mock import Mock

import pytest

from ads_sandbox_manager import __main__ as entrypoint
from ads_sandbox_manager.config import load_settings, size_bytes


@pytest.mark.parametrize(
    "value,want",
    [
        ("20Gi", 20 * 1024**3),
        ("2048Mi", 2 * 1024**3),
        ("100G", 100 * 1000**3),
        ("42", 42),
    ],
)
def test_size_parser_matches_entrypoint(value, want):
    assert size_bytes(value) == want


@pytest.mark.parametrize("value", ["0", "-1Gi", "2.5Gi", "2GB", "9223372036854775808", "2gi"])
def test_invalid_or_overflow_size_fails(value):
    with pytest.raises(ValueError):
        size_bytes(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("golden_slack", "0"),
        ("golden_slack", "2047Mi"),
        ("session_size", "1.5Gi"),
        ("golden_version", "latest"),
        ("golden_version", "v0.0.10/other"),
        ("golden_version", "v0.0.10-" + "x" * 60),
        ("namespace", "../other"),
        ("golden_image", ""),
        ("database_url", "sqlite:///:memory:"),
        ("poll_seconds", 0),
        ("control_seconds", float("inf")),
        ("node_fresh_seconds", float("nan")),
        ("ready_seconds", 0),
        ("barrier_seconds", float("nan")),
        ("idle_seconds", 0),
        ("detached_seconds", -1),
        ("cleanup_seconds", float("inf")),
        ("pvc_timeout_seconds", float("nan")),
        ("lifecycle_batch", 0),
        ("topic_replication_factor", 0),
        ("bake_seconds", 0),
        ("node_selector", []),
        ("node_selector", {}),
        ("tolerations", {}),
        ("resources", []),
        ("kafka_security_protocol", "INVALID"),
        ("kafka_security_protocol", "SASL_SSL"),
    ],
)
def test_invalid_configuration_fails_before_io(manager_settings, field, value):
    with pytest.raises(ValueError):
        replace(manager_settings, **{field: value})


@pytest.fixture
def manager_tls(manager_settings, tmp_path):
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
    return replace(manager_settings, tls_cert_path=cert, tls_key_path=key)


def configure(monkeypatch, settings):
    for name, value in {
        "GOLDEN_VERSION": settings.golden_version,
        "GOLDEN_IMAGE": settings.golden_image,
        "DATABASE_URL": settings.database_url,
        "KAFKA_BOOTSTRAP_SERVERS": settings.kafka_bootstrap_servers,
        "TLS_CERT_PATH": str(settings.tls_cert_path),
        "TLS_KEY_PATH": str(settings.tls_key_path),
        "KEYCLOAK_ISSUER": "https://identity.test",
        "KEYCLOAK_WELL_KNOWN_URL": "https://identity.test/.well-known/openid-configuration",
        "KEYCLOAK_CLIENT_SECRET": "fixture-only-secret",
        "SESSION_OBJECTS": json.dumps(
            {
                "guest_image": "registry.test/guest:1",
                "ipc_image": "registry.test/ipc:1",
                "ipc_storage_class": "local-path",
                "ipc_service_account": "ipc",
                "ipc_config_map": "ipc",
                "ipc_secret": "ipc",
                "ipc_tls_secret": "ipc-tls",
                "ipc_node_selector": {"ads.io/application-node": "true"},
            }
        ),
    }.items():
        monkeypatch.setenv("ADS_SANDBOX_MANAGER_" + name, value)
    monkeypatch.setenv("ADS_SESSION_SIZE", settings.session_size)


def test_load_settings_and_tls_before_clients(monkeypatch, manager_tls):
    configure(monkeypatch, manager_tls)
    monkeypatch.setenv("ADS_SANDBOX_MANAGER_TLS_CA_BUNDLE", str(manager_tls.tls_cert_path))
    settings = load_settings()
    assert settings.golden_name == "ads-sandbox-golden-v0-0-10"
    assert settings.golden_bytes == 22 * 1024**3
    assert settings.session_size == "20Gi"
    assert settings.database_url not in repr(settings)
    assert settings.keycloak_client_secret not in repr(settings)
    assert settings.barrier_seconds == 3
    assert settings.idle_seconds == 1800
    assert settings.detached_seconds == 7200
    assert settings.cleanup_seconds == settings.pvc_timeout_seconds == 120
    assert settings.lifecycle_batch == 50


def test_lifecycle_configuration_is_environment_overridable(monkeypatch, manager_tls):
    configure(monkeypatch, manager_tls)
    for name, value in {
        "IDLE_SECONDS": "60",
        "DETACHED_SECONDS": "90",
        "CLEANUP_SECONDS": "20",
        "PVC_TIMEOUT_SECONDS": "30",
        "LIFECYCLE_BATCH": "7",
    }.items():
        monkeypatch.setenv("ADS_SANDBOX_MANAGER_" + name, value)
    settings = load_settings()
    assert (
        settings.idle_seconds,
        settings.detached_seconds,
        settings.cleanup_seconds,
        settings.pvc_timeout_seconds,
        settings.lifecycle_batch,
    ) == (60, 90, 20, 30, 7)


@pytest.mark.parametrize(
    "name",
    ["SESSION_OBJECTS", "KEYCLOAK_ISSUER", "KEYCLOAK_WELL_KNOWN_URL", "KEYCLOAK_CLIENT_SECRET"],
)
def test_transit_configuration_required(monkeypatch, manager_tls, name):
    configure(monkeypatch, manager_tls)
    monkeypatch.delenv("ADS_SANDBOX_MANAGER_" + name)
    with pytest.raises(RuntimeError):
        load_settings()


@pytest.mark.parametrize("name", ["ADS_SESSION_SIZE", "ADS_SANDBOX_MANAGER_GOLDEN_VERSION"])
def test_release_coordinates_are_required_not_guessed(monkeypatch, manager_tls, name):
    configure(monkeypatch, manager_tls)
    monkeypatch.delenv(name)
    with pytest.raises(RuntimeError, match=name):
        load_settings()


@pytest.mark.parametrize("bad", ["TLS_CERT_PATH", "TLS_KEY_PATH", "TLS_CA_BUNDLE"])
def test_tls_failure_exits_before_any_network(monkeypatch, manager_tls, tmp_path, bad):
    configure(monkeypatch, manager_tls)
    invalid = tmp_path / "invalid.pem"
    invalid.write_text("not PEM")
    monkeypatch.setenv("ADS_SANDBOX_MANAGER_" + bad, str(invalid))
    result = subprocess.run(
        [sys.executable, "-m", "ads_sandbox_manager"],
        env=dict(os.environ),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "ssl.SSLError" in result.stderr
    assert "Started server process" not in result.stderr
    assert manager_tls.database_url not in result.stderr


def test_entrypoint_always_uses_tls(monkeypatch, manager_tls):
    monkeypatch.setattr(entrypoint, "load_settings", Mock(return_value=manager_tls))
    schema = Mock()
    monkeypatch.setattr(entrypoint, "prepare_schema", schema)
    app = Mock()
    monkeypatch.setattr(entrypoint, "create_app", Mock(return_value=app))
    server = Mock()
    factory = Mock(return_value=server)
    monkeypatch.setattr(entrypoint, "FailFastServer", factory)
    entrypoint.main()
    config = factory.call_args.args[0]
    assert config.ssl_certfile == str(manager_tls.tls_cert_path)
    assert config.ssl_keyfile == str(manager_tls.tls_key_path)
    assert config.app is app
    schema.assert_called_once()
    assert schema.call_args.kwargs["database_url"] == manager_tls.database_url
    assert schema.call_args.kwargs["tables"][0].name == "sandbox_session"
    server.run.assert_called_once()
