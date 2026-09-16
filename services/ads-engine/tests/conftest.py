from __future__ import annotations

from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ads_commons_beans import JwtVerifier
from ads_engine.config import Settings
from ads_engine.logconfig import configure_logging
from ads_engine.store import ActiveSessionStore
from engine_fakes import encode_access_token, make_verifier, new_rsa_key


@pytest.fixture(scope="session", autouse=True)
def _logging() -> None:
    configure_logging()


@pytest.fixture(scope="session")
def jwt_key() -> RSAPrivateKey:
    return new_rsa_key()


@pytest.fixture(scope="session")
def jwt_verifier(jwt_key: RSAPrivateKey) -> JwtVerifier:
    return make_verifier(jwt_key)


@pytest.fixture
def access_token(jwt_key: RSAPrivateKey) -> str:
    return encode_access_token(jwt_key)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        kafka_bootstrap_servers="kafka.test:9092",
        request_topic="ads.engine.request",
        output_topic="ads.engine.output",
        consumer_group="ads-engine",
        database_url="sqlite:///:memory:",
        ping_interval_seconds=10,
        ack_timeout_seconds=10,
        keycloak_well_known_url="https://keycloak.test/realms/ads/.well-known/openid-configuration",
        keycloak_issuer="https://keycloak.test/realms/ads",
        keycloak_audience="ads-engine",
        keycloak_client_id="ads",
        keycloak_client_secret="engine-client-secret",
        ack_audience="ads",
        allowed_callers=frozenset({"ads"}),
        tls_ca_bundle=None,
    )


@pytest.fixture
def store(settings: Settings) -> Iterator[ActiveSessionStore]:
    yield ActiveSessionStore(settings)
