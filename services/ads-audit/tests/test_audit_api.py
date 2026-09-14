from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from litestar.testing import TestClient

from ads_audit.app import create_app
from ads_audit.config import Settings
from ads_audit.repository import InMemoryAuditRepository
from ads_policy.contract import AuditEvent
from audit_helpers import TOKEN, denied


class _Broker:
    """No RabbitMQ in the fast suite: the consumer is started against this."""

    async def channel(self) -> _Channel:
        return _Channel()


class _Channel:
    async def set_qos(self, prefetch_count: int) -> None:
        return None

    async def declare_exchange(self, name: str, kind: object, durable: bool) -> _Exchange:
        return _Exchange()

    async def declare_queue(self, name: str, durable: bool) -> _Queue:
        return _Queue()


class _Exchange:
    pass


class _Queue:
    async def bind(self, exchange: object, routing_key: str) -> None:
        return None

    async def consume(self, callback: object) -> None:
        return None


@pytest.fixture
def api(settings: Settings, repository: InMemoryAuditRepository) -> Iterator[TestClient]:
    app = create_app(settings, repository, _Broker())  # type: ignore[arg-type]
    with TestClient(app=app) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        yield client


def _seed(repository: InMemoryAuditRepository, *events: AuditEvent) -> None:
    async def fill() -> None:
        for event in events:
            await repository.append(event)

    asyncio.run(fill())


def test_health_is_public(settings: Settings, repository: InMemoryAuditRepository) -> None:
    app = create_app(settings, repository, _Broker())  # type: ignore[arg-type]
    with TestClient(app=app) as client:
        assert client.get("/health/live").status_code == 200


def test_the_api_needs_the_token(settings: Settings, repository: InMemoryAuditRepository) -> None:
    app = create_app(settings, repository, _Broker())  # type: ignore[arg-type]
    with TestClient(app=app) as client:
        assert client.get("/audit/runs/run-1/budget").status_code == 401
        client.headers["authorization"] = "Bearer wrong-token-wrong-token"
        assert client.get("/audit/runs/run-1/budget").status_code == 401


def test_the_run_budget_is_served(api: TestClient, repository: InMemoryAuditRepository) -> None:
    _seed(repository, denied(resource="ads-client-secret"), denied(resource="git-token", weight=3))
    payload = api.get("/audit/runs/run-1/budget").json()
    assert payload == {"run_id": "run-1", "budget": 8}
    assert api.get("/audit/runs/run-2/budget").json()["budget"] == 0


def test_the_subject_budget_is_served(api: TestClient, repository: InMemoryAuditRepository) -> None:
    _seed(repository, denied(run_id="run-1"), denied(run_id="run-2"))
    payload = api.get("/audit/subjects/alice/budget").json()
    assert payload["subject"] == "alice"
    assert payload["budget"] == 5 + 5 * 3
    assert api.get("/audit/subjects/bob/budget").json()["budget"] == 0


def test_the_journal_offers_no_way_to_remove_a_row() -> None:
    repository = InMemoryAuditRepository()
    for forbidden in ("delete", "remove", "purge", "truncate"):
        assert not hasattr(repository, forbidden)
