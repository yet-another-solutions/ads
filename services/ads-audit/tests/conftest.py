from __future__ import annotations

from pathlib import Path

import pytest

from ads_audit.config import Settings
from ads_audit.logconfig import configure_logging
from ads_audit.repository import InMemoryAuditRepository
from ads_audit.service import AuditService
from audit_helpers import TOKEN


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
    )
