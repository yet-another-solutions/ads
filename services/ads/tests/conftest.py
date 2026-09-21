from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest
from litestar import Litestar
from litestar.testing import TestClient
from sqlalchemy import Engine

from ads.app import build_session_config, create_app, create_schema
from ads.config import Settings, load_settings
from ads.db import create_db_engine
from ads.logconfig import configure_logging
from ads_commons_beans import JwtVerifier
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.service import PolicyService
from tests.policy import DirectPolicyClient, policy_service
from tests.threadline_fakes import (
    FakeAuthenticator,
    FakeOidcVerifier,
    FakePreferences,
    FakeTokens,
    RecordingKafka,
)


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
        tls_cert_path=cert,
        tls_key_path=key,
        tls_ca_bundle=None,
        bind_host="127.0.0.1",
        port=8080,
        database_url="sqlite:///:memory:",
        kafka_bootstrap_servers="",
        audit_flush_seconds=0.01,
    )


@pytest.fixture
def db_engine(settings: Settings) -> Iterator[Engine]:
    engine = create_db_engine(settings.database_url)
    create_schema(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def preferences() -> FakePreferences:
    return FakePreferences()


@pytest.fixture
def kafka() -> RecordingKafka:
    return RecordingKafka()


@pytest.fixture
def tokens() -> FakeTokens:
    return FakeTokens()


@pytest.fixture
def authenticator() -> FakeAuthenticator:
    return FakeAuthenticator()


@pytest.fixture
def oidc_verifier() -> JwtVerifier:
    return cast(JwtVerifier, FakeOidcVerifier())


@pytest.fixture
def app(
    settings: Settings,
    db_engine: Engine,
    preferences: FakePreferences,
    kafka: RecordingKafka,
    tokens: FakeTokens,
    authenticator: FakeAuthenticator,
    oidc_verifier: JwtVerifier,
    journal: CollectingAuditSink,
) -> Litestar:
    return create_app(
        settings,
        engine=db_engine,
        preferences=preferences,
        kafka=kafka,
        tokens=tokens,
        jwt_verifier=authenticator,
        oidc_verifier=oidc_verifier,
        journal=journal,
    )


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
    """What ads publishes: an auditor's reading, and decisions the policy service missed."""
    return CollectingAuditSink()


@pytest.fixture
def audit(journal: CollectingAuditSink) -> BufferedAuditSink:
    return BufferedAuditSink(journal)
