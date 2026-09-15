from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from litestar import Litestar
from litestar.testing import TestClient
from sqlalchemy import Engine, event

from ads_commons.security import JwtVerifier
from ads_preferences.app import create_app, create_schema
from ads_preferences.config import Settings
from ads_preferences.db import create_db_engine
from ads_preferences.logconfig import configure_logging
from preference_tokens import encode_token, make_verifier, new_rsa_key


@pytest.fixture(scope="session", autouse=True)
def _logging() -> None:
    configure_logging()


@pytest.fixture
def rsa_key() -> RSAPrivateKey:
    return new_rsa_key()


@pytest.fixture
def jwt_verifier(rsa_key: RSAPrivateKey) -> JwtVerifier:
    return make_verifier(rsa_key)


@pytest.fixture
def engine() -> Engine:
    db_engine = create_db_engine("sqlite:///:memory:")
    create_schema(db_engine)
    return db_engine


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    return Settings(
        keycloak_well_known_url="https://kc/realms/ads/.well-known/openid-configuration",
        keycloak_issuer="https://keycloak.test/realms/ads",
        keycloak_audience="ads-preferences",
        keycloak_client_id="ads",
        allowed_callers=frozenset({"ads"}),
        database_url="sqlite:///:memory:",
        tls_cert_path=cert,
        tls_key_path=key,
        tls_ca_bundle=None,
        bind_host="127.0.0.1",
        port=8080,
    )


@pytest.fixture
def app(settings: Settings, jwt_verifier: JwtVerifier, engine: Engine) -> Litestar:
    return create_app(settings, jwt_verifier=jwt_verifier, engine=engine)


@pytest.fixture
def client(app: Litestar) -> Iterator[TestClient]:
    with TestClient(app=app) as test_client:
        yield test_client


@pytest.fixture
def user_token(rsa_key: RSAPrivateKey) -> str:
    return encode_token(rsa_key)


@pytest.fixture
def sql_count(engine: Engine) -> Iterator[list[int]]:
    counter = [0]

    def _count(*_args: object, **_kwargs: object) -> None:
        counter[0] += 1

    event.listen(engine, "before_cursor_execute", _count)
    try:
        yield counter
    finally:
        event.remove(engine, "before_cursor_execute", _count)
