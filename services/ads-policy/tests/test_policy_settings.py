from __future__ import annotations

from pathlib import Path

import pytest

from ads_policy.config import (
    Mode,
    Settings,
    load_governance_settings,
    load_settings,
    load_tls_context,
)


def _env(monkeypatch: pytest.MonkeyPatch, cert: Path, key: Path) -> None:
    monkeypatch.setenv("ADS_POLICY_API_TOKEN", "policy-api-token-32-bytes-long")
    monkeypatch.setenv("ADS_REDIS_URL", "rediss://ads-redis:6379/0")
    monkeypatch.setenv("ADS_AMQP_URL", "amqps://ads-rabbitmq:5671/")
    monkeypatch.setenv("ADS_TLS_CERT_PATH", str(cert))
    monkeypatch.setenv("ADS_TLS_KEY_PATH", str(key))


def _tls(tmp_path: Path) -> tuple[Path, Path]:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    return cert, key


def test_load_settings_requires_tls_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _env(monkeypatch, tmp_path / "missing.crt", tmp_path / "missing.key")
    with pytest.raises(RuntimeError, match="ADS_TLS_CERT_PATH must exist"):
        load_settings()


def test_load_settings_requires_an_api_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cert, key = _tls(tmp_path)
    _env(monkeypatch, cert, key)
    monkeypatch.setenv("ADS_POLICY_API_TOKEN", "short")
    with pytest.raises(RuntimeError, match="ADS_POLICY_API_TOKEN"):
        load_settings()
    monkeypatch.delenv("ADS_POLICY_API_TOKEN")
    with pytest.raises(RuntimeError, match="ADS_POLICY_API_TOKEN is required"):
        load_settings()


def test_load_settings_requires_a_run_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cert, key = _tls(tmp_path)
    _env(monkeypatch, cert, key)
    monkeypatch.delenv("ADS_REDIS_URL")
    with pytest.raises(RuntimeError, match="ADS_REDIS_URL is required"):
        load_settings()


def test_load_settings_requires_an_audit_exchange(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cert, key = _tls(tmp_path)
    _env(monkeypatch, cert, key)
    monkeypatch.delenv("ADS_AMQP_URL")
    with pytest.raises(RuntimeError, match="ADS_AMQP_URL is required"):
        load_settings()


def test_load_tls_context_rejects_garbage_pem(tmp_path: Path) -> None:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("not-a-cert")
    key.write_text("not-a-key")
    settings = Settings(api_token="policy-api-token-32", tls_cert_path=cert, tls_key_path=key)
    with pytest.raises(RuntimeError, match="could not be loaded"):
        load_tls_context(settings)


def test_governance_settings_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_POLICY_MODE", "review")
    monkeypatch.setenv("ADS_EGRESS_ALLOWLIST", "mirror.interlab, git-proxy.interlab")
    monkeypatch.setenv("ADS_PROTECTED_BRANCHES", "main")
    monkeypatch.setenv("ADS_POLICY_DENY_ON_ERROR", "false")
    monkeypatch.setenv("ADS_RUN_TTL_SECONDS", "900")
    settings = load_governance_settings()
    assert settings.mode is Mode.REVIEW
    assert settings.egress_allowlist == ("mirror.interlab", "git-proxy.interlab")
    assert settings.protected_branches == ("main",)
    assert settings.deny_on_policy_error is False
    assert settings.run_ttl_seconds == 900


def test_the_run_lifetime_defaults_to_an_hour() -> None:
    assert load_governance_settings().run_ttl_seconds == 3600


def test_the_sandbox_is_told_to_the_service_not_discovered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert load_governance_settings().sandbox_available is True
    monkeypatch.setenv("ADS_SANDBOX_AVAILABLE", "false")
    assert load_governance_settings().sandbox_available is False


def test_a_nonsense_run_lifetime_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_RUN_TTL_SECONDS", "forever")
    with pytest.raises(RuntimeError, match="whole number of seconds"):
        load_governance_settings()
    monkeypatch.setenv("ADS_RUN_TTL_SECONDS", "0")
    with pytest.raises(RuntimeError, match="greater than zero"):
        load_governance_settings()


def test_an_unknown_mode_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADS_POLICY_MODE", "advisory")
    with pytest.raises(RuntimeError, match="ADS_POLICY_MODE"):
        load_governance_settings()
