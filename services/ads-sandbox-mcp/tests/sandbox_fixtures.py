"""Reusable MCP fixtures for service tests and the cross-service handshake proof."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from ads_commons_schema import mapped_tables, prepare_schema
from ads_sandbox_mcp.config import Settings
from ads_sandbox_mcp.store import InFlight
from sandbox_support import Harness


@pytest.fixture(scope="session")
def sandbox_database_url() -> Iterator[str]:
    configured = os.environ.get("ADS_MCP_TEST_DATABASE_URL")
    if configured:
        yield configured
    else:
        from testcontainers.postgres import PostgresContainer

        # CI supplies Docker. No SQLite fallback: it would hide row-lock and leader-lock bugs.
        with PostgresContainer("postgres:16-alpine", driver="psycopg") as postgres:
            yield postgres.get_connection_url()


@pytest.fixture
def sandbox_settings() -> Settings:
    # No database or network access just to construct settings or test composition.
    return Settings(
        database_url="postgresql+psycopg://fixture:fixture@localhost/mcp",
        keycloak_well_known_url="https://identity.test/.well-known/openid-configuration",
        keycloak_issuer="https://identity.test",
        keycloak_client_secret="not-a-real-secret",
        tls_cert_path=Path("/unused/cert"),
        tls_key_path=Path("/unused/key"),
        kafka_bootstrap_servers="unused.test:9092",
        timeout_seconds=0.4,
        allowed_hosts=("testserver.local",),
    )


@pytest.fixture
def sandbox_engine(sandbox_database_url: str) -> Iterator[AsyncEngine]:
    # Disposable PostgreSQL only: the service owns its independent Alembic head.
    service_dir = Path(__file__).parents[1]
    prepare_schema(
        alembic_ini=service_dir / "alembic.ini",
        database_url=sandbox_database_url,
        tables=mapped_tables(InFlight),
    )
    sync = create_engine(sandbox_database_url)
    try:
        with sync.begin() as connection:
            connection.execute(text("DELETE FROM sandbox_execution"))
    finally:
        sync.dispose()
    engine = create_async_engine(sandbox_database_url, poolclass=NullPool)
    try:
        yield engine
    finally:
        asyncio.run(engine.dispose())


@pytest.fixture
def harness(
    sandbox_settings: Settings, sandbox_database_url: str, sandbox_engine: AsyncEngine
) -> Harness:
    return Harness(replace(sandbox_settings, database_url=sandbox_database_url), sandbox_engine)


@pytest.fixture
def long_harness(harness: Harness) -> Harness:
    harness.settings = replace(harness.settings, timeout_seconds=3)
    harness.rebuild()
    return harness
