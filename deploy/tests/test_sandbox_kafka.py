"""Scoped broker credentials reach every MCP/IPC client, never anonymous fallback."""

from importlib import import_module
from unittest.mock import Mock
from uuid import uuid4

import pytest


@pytest.mark.parametrize("component", ["mcp", "ipc"])
def test_sasl_environment_reaches_all_clients(component, monkeypatch, tmp_path):
    module = import_module(f"ads_sandbox_{component}.config")
    prefix = f"ADS_SANDBOX_{component.upper()}_"
    env = {
        "DATABASE_URL": "postgresql+psycopg://unused.invalid/unused",
        "SANDBOX_ID": str(uuid4()),
        "PID_DIRECTORY": str(tmp_path),
        "KEYCLOAK_WELL_KNOWN_URL": "https://unused.invalid/discovery",
        "KEYCLOAK_ISSUER": "https://unused.invalid",
        "KEYCLOAK_CLIENT_SECRET": "test-client-secret",
        "TLS_CERT_PATH": str(tmp_path / "cert"),
        "TLS_KEY_PATH": str(tmp_path / "key"),
        "KAFKA_BOOTSTRAP_SERVERS": "unused.invalid:9092",
        "KAFKA_SECURITY_PROTOCOL": "SASL_PLAINTEXT",
        "KAFKA_SASL_MECHANISM": "PLAIN",
        "KAFKA_SASL_USERNAME": f"ads-sandbox-{component}",
        "KAFKA_SASL_PASSWORD": "fixture-broker-password",
    }
    for key, value in env.items():
        monkeypatch.setenv(prefix + key, value)
    monkeypatch.setattr(module, "load_tls_context", Mock())
    settings = module.load_settings()
    assert env["KAFKA_SASL_PASSWORD"] not in repr(settings)
    expected = {
        "bootstrap_servers": env["KAFKA_BOOTSTRAP_SERVERS"],
        "security_protocol": "SASL_PLAINTEXT",
        "sasl_mechanism": "PLAIN",
        "sasl_plain_username": env["KAFKA_SASL_USERNAME"],
        "sasl_plain_password": env["KAFKA_SASL_PASSWORD"],
    }
    assert settings.kafka_options() == expected
    ioc = import_module(f"ads_sandbox_{component}.ioc")
    producer = Mock()
    monkeypatch.setattr(ioc, "AIOKafkaProducer", producer)
    provider = ioc.AppProvider(settings)
    provider.producer(settings)
    producer.assert_called_once_with(**expected)
    consumer = Mock()
    if component == "mcp":
        monkeypatch.setattr(ioc, "AIOKafkaConsumer", consumer)
        provider.consumer(settings)
        assert consumer.call_count == 1
    else:
        kafka = import_module("ads_sandbox_ipc.kafka")
        monkeypatch.setattr(kafka, "AIOKafkaConsumer", consumer)
        kafka.KafkaRuntime(settings, Mock(), Mock(), Mock())
        assert consumer.call_count == 2  # execution/lifecycle and independent ping loop
    for call in consumer.call_args_list:
        assert expected.items() <= call.kwargs.items()
        assert call.kwargs["enable_auto_commit"] is False
    for key in ("KAFKA_SASL_USERNAME", "KAFKA_SASL_PASSWORD"):
        monkeypatch.delenv(prefix + key)
        with pytest.raises(ValueError, match="SASL username and password"):
            module.load_settings()
        monkeypatch.setenv(prefix + key, env[key])
    for protocol in ("typo", "SASL_SSL"):
        monkeypatch.setenv(prefix + "KAFKA_SECURITY_PROTOCOL", protocol)
        with pytest.raises(ValueError, match="unsupported Kafka"):
            module.load_settings()
    monkeypatch.setenv(prefix + "KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    monkeypatch.delenv(prefix + "KAFKA_SASL_USERNAME")
    monkeypatch.delenv(prefix + "KAFKA_SASL_PASSWORD")
    assert module.load_settings().kafka_options()["security_protocol"] == "PLAINTEXT"
