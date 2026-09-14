from __future__ import annotations

from collections.abc import Iterator

import pytest

from ads_engine.config import Settings
from ads_engine.logconfig import configure_logging
from ads_engine.store import ActiveSessionStore


@pytest.fixture(scope="session", autouse=True)
def _logging() -> None:
    configure_logging()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        kafka_bootstrap_servers="kafka.test:9092",
        request_topic="ads.engine.request",
        output_topic="ads.engine.output",
        consumer_group="ads-engine",
        database_url="sqlite:///:memory:",
        ping_interval_seconds=10,
        keycloak_well_known_url="https://keycloak.test/realms/ads/.well-known/openid-configuration",
        keycloak_issuer="https://keycloak.test/realms/ads",
        keycloak_audience="ads-engine",
    )


@pytest.fixture
def store() -> Iterator[ActiveSessionStore]:
    yield ActiveSessionStore("sqlite:///:memory:")
