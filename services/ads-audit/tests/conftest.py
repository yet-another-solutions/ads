from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from ads_audit.config import Settings
from ads_audit.logconfig import configure_logging
from ads_audit.repository import InMemoryAuditRepository
from ads_audit.service import AuditService
from audit_helpers import SESSION_SECRET, TOKEN


@pytest.fixture(scope="session", autouse=True)
def _logging() -> None:
    configure_logging()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def repository() -> InMemoryAuditRepository:
    return InMemoryAuditRepository()


@pytest.fixture
def service(repository: InMemoryAuditRepository) -> AuditService:
    return AuditService(repository)


@pytest.fixture(scope="session")
def postgres_url() -> Iterator[str]:
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16-alpine", driver="asyncpg") as postgres:
        yield postgres.get_connection_url()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    return Settings(
        api_token=TOKEN,
        tls_cert_path=cert,
        tls_key_path=key,
        amqp_url="amqp://unused",
        database_url="postgresql+asyncpg://unused/unused",
        session_secret=SESSION_SECRET,
        public_base_url="https://audit.test",
    )
