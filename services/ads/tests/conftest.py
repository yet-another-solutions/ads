from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from litestar import Litestar
from litestar.testing import TestClient
from sqlalchemy import Engine

from ads.app import build_session_config, create_app, create_schema
from ads.config import Settings
from ads.db import create_db_engine
from ads.logconfig import configure_logging
from tests.threadline_fakes import (
    FakeAuthenticator,
    FakePreferences,
    FakeTokens,
    RecordingKafka,
)


@pytest.fixture(scope="session", autouse=True)
def _logging() -> None:
    configure_logging()


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
def app(
    settings: Settings,
    db_engine: Engine,
    preferences: FakePreferences,
    kafka: RecordingKafka,
    tokens: FakeTokens,
    authenticator: FakeAuthenticator,
) -> Litestar:
    return create_app(
        settings,
        engine=db_engine,
        preferences=preferences,
        kafka=kafka,
        tokens=tokens,
        jwt_verifier=authenticator,
    )


@pytest.fixture
def client(app: Litestar, settings: Settings) -> Iterator[TestClient]:
    with TestClient(app=app, session_config=build_session_config(settings)) as test_client:
        yield test_client
