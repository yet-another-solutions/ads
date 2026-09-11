from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from litestar import Litestar
from litestar.testing import TestClient

from ads.app import build_session_config, create_app
from ads.config import Settings
from ads.logconfig import configure_logging


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
