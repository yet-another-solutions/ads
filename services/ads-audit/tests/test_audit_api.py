from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime

import msgspec
import pytest
from litestar.testing import TestClient

from ads_audit.app import create_app
from ads_audit.config import Settings
from ads_audit.repository import InMemoryAuditRepository
from ads_audit.service import MAX_PAGE
from ads_policy.contract import AuditEvent, Capability, InterceptionPoint
from audit_helpers import TOKEN, SilentBroker, denied


@pytest.fixture
def api(settings: Settings, repository: InMemoryAuditRepository) -> Iterator[TestClient]:
    app = create_app(settings, repository, SilentBroker())  # type: ignore[arg-type]
    with TestClient(app=app) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        yield client


def _seed(repository: InMemoryAuditRepository, *events: AuditEvent) -> None:
    async def fill() -> None:
        for event in events:
            await repository.append(event)

    asyncio.run(fill())


def test_health_is_public(settings: Settings, repository: InMemoryAuditRepository) -> None:
    app = create_app(settings, repository, SilentBroker())  # type: ignore[arg-type]
    with TestClient(app=app) as client:
        assert client.get("/health/live").status_code == 200


def test_the_api_needs_the_token(settings: Settings, repository: InMemoryAuditRepository) -> None:
    app = create_app(settings, repository, SilentBroker())  # type: ignore[arg-type]
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


def test_the_events_and_budget_of_a_conversation_are_served(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    chat = "3f2b6c1e-0000-4000-8000-000000000001"
    _seed(
        repository,
        denied(run_id="run-1", resource="one", conversation=chat),
        denied(run_id="run-2", resource="two", weight=3, conversation=chat),
        denied(run_id="run-3", resource="elsewhere"),
    )
    events = api.get(f"/audit/conversations/{chat}").json()["events"]
    assert {event["run_id"] for event in events} == {"run-1", "run-2"}
    assert api.get(f"/audit/conversations/{chat}/budget").json() == {
        "conversation": chat,
        "budget": 8,
        "blocked_at": None,
        "lifted_at": None,
        "lifted_by": "",
    }


def test_a_blocked_conversation_says_when_it_was_blocked(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    chat = "3f2b6c1e-0000-4000-8000-000000000001"
    asyncio.run(repository.block_conversation(chat, 31))
    assert api.get(f"/audit/conversations/{chat}/budget").json()["blocked_at"] is not None


def test_an_auditor_lifts_a_block_and_the_record_says_who(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    chat = "3f2b6c1e-0000-4000-8000-000000000001"
    asyncio.run(repository.block_conversation(chat, 31))
    lifted = api.delete(f"/audit/conversations/{chat}/block", params={"by": "alice the auditor"})
    assert lifted.status_code == 200
    assert lifted.json()["lifted_by"] == "alice the auditor"
    assert lifted.json()["lifted_at"] is not None
    standing = asyncio.run(repository.conversation_block(chat))
    assert standing is not None and not standing.in_force
    assert api.get(f"/audit/conversations/{chat}/budget").json()["blocked_at"] is None


def test_lifting_a_block_nobody_placed_is_not_found(api: TestClient) -> None:
    chat = "3f2b6c1e-0000-4000-8000-000000000009"
    assert (
        api.delete(f"/audit/conversations/{chat}/block", params={"by": "alice"}).status_code == 404
    )


def test_a_lift_says_who_lifted_it(api: TestClient, repository: InMemoryAuditRepository) -> None:
    chat = "3f2b6c1e-0000-4000-8000-000000000001"
    asyncio.run(repository.block_conversation(chat, 31))
    assert api.delete(f"/audit/conversations/{chat}/block", params={"by": " "}).status_code == 400
    assert api.delete(f"/audit/conversations/{chat}/block").status_code == 400


def _at(minute: int, event_id: str) -> AuditEvent:
    return msgspec.structs.replace(
        denied(),
        event_id=event_id,
        recorded_at=datetime(2026, 9, 15, 12, minute, tzinfo=UTC),
    )


def test_the_events_of_a_run_are_served(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, denied(resource="ads-client-secret"), denied(run_id="run-2"))
    events = api.get("/audit/runs/run-1").json()["events"]
    assert [event["resource"] for event in events] == ["ads-client-secret"]
    assert events[0]["capability"] == Capability.SECRET_READ.value
    assert events[0]["point"] == InterceptionPoint.CALL.value
    assert api.get("/audit/runs/nothing-here").json()["events"] == []


def test_the_events_of_a_subject_are_served(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, denied(run_id="run-1"), denied(run_id="run-2"), denied(subject="bob"))
    events = api.get("/audit/subjects/alice").json()["events"]
    assert {event["run_id"] for event in events} == {"run-1", "run-2"}
    assert api.get("/audit/subjects/bob").json()["events"][0]["subject"] == "bob"


def test_the_events_of_a_run_page_like_the_journal_does(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, *(_at(minute, f"e{minute}") for minute in range(1, 4)))
    first = api.get("/audit/runs/run-1?limit=2").json()
    assert [event["event_id"] for event in first["events"]] == ["e3", "e2"]
    assert first["next_cursor"] is not None
    rest = api.get(f"/audit/runs/run-1?limit=2&cursor={first['next_cursor']}").json()
    assert [event["event_id"] for event in rest["events"]] == ["e1"]
    assert rest["next_cursor"] is None


def test_a_run_page_is_capped_like_the_journal_is(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, *(_at(minute, f"e{minute}") for minute in range(1, 6)))
    page = api.get(f"/audit/runs/run-1?limit={MAX_PAGE * 10}").json()
    assert len(page["events"]) == 5


def test_the_journal_comes_newest_first(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, _at(1, "e1"), _at(2, "e2"), _at(3, "e3"))
    page = api.get("/audit/events").json()
    assert [event["event_id"] for event in page["events"]] == ["e3", "e2", "e1"]
    assert page["next_cursor"] is None


def test_the_journal_pages_through_without_repeating(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, *(_at(minute, f"e{minute}") for minute in range(1, 6)))
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(3):
        query = f"/audit/events?limit=2{f'&cursor={cursor}' if cursor else ''}"
        page = api.get(query).json()
        seen += [event["event_id"] for event in page["events"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == ["e5", "e4", "e3", "e2", "e1"]
    assert cursor is None


def test_a_page_says_when_there_is_more(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, _at(1, "e1"), _at(2, "e2"), _at(3, "e3"))
    page = api.get("/audit/events?limit=2").json()
    assert [event["event_id"] for event in page["events"]] == ["e3", "e2"]
    assert page["next_cursor"] is not None


def test_an_unreadable_cursor_is_refused(api: TestClient) -> None:
    assert api.get("/audit/events?cursor=nonsense").status_code == 400


def test_a_cursor_without_a_time_zone_is_refused_rather_than_guessed_at(
    api: TestClient,
) -> None:
    assert api.get("/audit/events?cursor=2026-09-15T12:01:00|e1").status_code == 400


def test_the_service_caps_the_page_size_the_caller_asks_for(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, *(_at(minute, f"e{minute}") for minute in range(1, 6)))
    page = api.get(f"/audit/events?limit={MAX_PAGE * 10}").json()
    assert len(page["events"]) == 5


def test_the_journal_shows_moments_in_the_zone_the_caller_asks_for(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, _at(1, "e1"))
    in_utc = api.get("/audit/events").json()["events"][0]["recorded_at"]
    in_moscow = api.get("/audit/events?tz=Europe/Moscow").json()["events"][0]["recorded_at"]
    assert in_utc.endswith("Z") or in_utc.endswith("+00:00")
    assert in_moscow.endswith("+03:00")
    assert datetime.fromisoformat(in_moscow) == datetime.fromisoformat(in_utc)


def test_events_of_a_conversation_and_its_block_follow_the_same_zone(
    api: TestClient, repository: InMemoryAuditRepository
) -> None:
    chat = "3f2b6c1e-0000-4000-8000-000000000001"
    _seed(repository, denied(conversation=chat))
    asyncio.run(repository.block_conversation(chat, 31))
    events = api.get(f"/audit/conversations/{chat}?tz=Europe/Moscow").json()["events"]
    budget = api.get(f"/audit/conversations/{chat}/budget?tz=Europe/Moscow").json()
    assert events[0]["recorded_at"].endswith("+03:00")
    assert budget["blocked_at"].endswith("+03:00")


def test_an_unknown_zone_is_refused(api: TestClient) -> None:
    assert api.get("/audit/events?tz=Mars/Olympus").status_code == 400


def test_the_journal_offers_no_way_to_remove_a_row() -> None:
    repository = InMemoryAuditRepository()
    for forbidden in ("delete", "remove", "purge", "truncate"):
        assert not hasattr(repository, forbidden)
