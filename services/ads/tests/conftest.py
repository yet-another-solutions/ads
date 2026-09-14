from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from litestar import Litestar
from litestar.testing import TestClient

from ads.app import build_session_config, create_app
from ads.config import Settings, load_settings
from ads.logconfig import configure_logging
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.service import PolicyService
from tests.policy import DirectPolicyClient, policy_service


@pytest.fixture(scope="session", autouse=True)
def _logging() -> None:
    configure_logging()


@pytest.fixture(autouse=True)
def _fresh_settings() -> Iterator[None]:
    """``load_settings`` is cached for the process, so each test starts from empty."""
    load_settings.cache_clear()
    yield
    load_settings.cache_clear()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    return Settings(
        keycloak_well_known_url="http://keycloak.test/realms/ads/.well-known/openid-configuration",
        keycloak_issuer="http://keycloak.test/realms/ads",
        keycloak_client_id="ads",
        keycloak_client_secret="test-secret",
        keycloak_audience="ads",
        keycloak_role="user",
        session_secret="test-session-secret-32b!",
        public_base_url="http://testserver",
        data_dir=tmp_path / "data",
        tls_cert_path=cert,
        tls_key_path=key,
        tls_ca_bundle=None,
        bind_host="127.0.0.1",
        port=8080,
    )


@pytest.fixture
def app(settings: Settings) -> Litestar:
    return create_app(settings)


@pytest.fixture
def client(app: Litestar, settings: Settings) -> Iterator[TestClient]:
    with TestClient(app=app, session_config=build_session_config(settings)) as test_client:
        yield test_client


@pytest.fixture
def service_journal() -> CollectingAuditSink:
    """What the policy service publishes: every decision it actually made."""
    return CollectingAuditSink()


@pytest.fixture
def service(service_journal: CollectingAuditSink) -> PolicyService:
    return policy_service(service_journal)


@pytest.fixture
def policy_client(service: PolicyService) -> DirectPolicyClient:
    return DirectPolicyClient(service)


@pytest.fixture
def journal() -> CollectingAuditSink:
    """What the PEP publishes: only the decisions the policy service never saw."""
    return CollectingAuditSink()


@pytest.fixture
def audit(journal: CollectingAuditSink) -> BufferedAuditSink:
    return BufferedAuditSink(journal)
