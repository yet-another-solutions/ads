from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from litestar.testing import TestClient

from ads_audit.app import create_app
from ads_audit.config import Settings
from ads_audit.repository import InMemoryAuditRepository
from ads_commons.security import InvalidAccessToken
from ads_commons_web.identity import ACCESS_TOKEN_SESSION_KEY
from ads_commons_web.session import cookie_session
from ads_commons_web.session_binder import SessionBinder
from ads_policy.client import PolicyUnavailable
from ads_policy.contract import (
    UNCHECKED_SOURCE_RULE,
    AuditEvent,
    Capability,
    Effect,
    SourceChecks,
    Switch,
)
from audit_helpers import SESSION_SECRET, SilentBroker

AUDITOR = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
CHAT = "3f2b6c1e-0000-4000-8000-000000000001"
NOW = datetime.now(UTC).replace(microsecond=0)


class _Verifier:
    def verified_claims(self, token: str, *, verify_exp: bool = True) -> dict[str, Any]:
        sub, _, roles = token.partition(":")
        if not sub:
            raise InvalidAccessToken("no subject")
        return {
            "sub": sub,
            "name": "Ada Auditor",
            "email": "ada@example.com",
            "sid": f"sid-{sub}",
            "exp": int(time.time()) + 3600,
            "realm_access": {"roles": [role for role in roles.split(",") if role]},
        }


class _NoRefresh:
    async def refresh_tokens(self, refresh_token: str) -> dict[str, Any]:
        raise AssertionError("no refresh in these tests")


class _NoRefreshTokens:
    async def load(self, sid: str) -> str | None:
        return None

    async def save(self, sid: str, user_id: uuid.UUID, refresh_token: str) -> None:
        return None

    async def delete(self, sid: str) -> None:
        return None


class _Policy:
    def __init__(self) -> None:
        self.lifted: list[str] = []
        self.answering = True

    async def block(self, conversation: str, budget: int) -> None:
        return None

    async def lift(self, conversation: str) -> None:
        self.lifted.append(conversation)

    async def sources(self) -> Sequence[SourceChecks]:
        if not self.answering:
            raise PolicyUnavailable("down")
        return [SourceChecks("mcp:jira", Switch.OFF), SourceChecks("opencode", Switch.ENFORCE)]


def _event(
    minutes_ago: int,
    *,
    effect: Effect = Effect.ALLOW,
    source: str = "",
    tool: str = "",
    rule_id: str = "fs.read.workdir",
    content: str | None = None,
) -> AuditEvent:
    return AuditEvent(
        run_id="run-1",
        subject=str(AUDITOR),
        capability=Capability.FS_READ,
        resource=f"/workspace/{minutes_ago}",
        effect=effect,
        rule_id=rule_id,
        weight=0,
        policy_hash="hash",
        content=content,
        conversation=CHAT,
        source=source,
        tool=tool,
        event_id=f"event-{minutes_ago:03d}",
        recorded_at=NOW - timedelta(minutes=minutes_ago),
    )


def _seed(repository: InMemoryAuditRepository, *events: AuditEvent) -> None:
    async def fill() -> None:
        for event in events:
            await repository.append(event)

    asyncio.run(fill())


@pytest.fixture
def policy() -> _Policy:
    return _Policy()


@pytest.fixture
def ui(
    settings: Settings, repository: InMemoryAuditRepository, policy: _Policy
) -> Iterator[TestClient]:
    app = create_app(
        settings,
        repository,
        SilentBroker(),  # type: ignore[arg-type]
        policy_blocker=policy,
        policy_sources=policy,
    )
    app.state.session_binder = SessionBinder(
        _Verifier(),  # type: ignore[arg-type]
        _NoRefresh(),
        _NoRefreshTokens(),
        settings.keycloak_client_id,
    )
    session = cookie_session(SESSION_SECRET, settings.public_base_url)
    with TestClient(app=app, base_url="https://audit.test", session_config=session) as client:
        yield client


def _log_in(client: TestClient, roles: str = "auditor") -> None:
    client.set_session_data({ACCESS_TOKEN_SESSION_KEY: f"{AUDITOR}:{roles}"})


def test_a_stranger_is_sent_to_log_in(ui: TestClient) -> None:
    response = ui.get("/journal?source=mcp:jira", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert response.headers["location"] == "/login"


def test_someone_without_the_auditor_role_is_refused(ui: TestClient) -> None:
    _log_in(ui, roles="user")
    assert ui.get("/journal").status_code == 403


def test_the_journal_api_needs_no_browser_session(ui: TestClient) -> None:
    assert ui.get("/audit/events").status_code == 401


def test_the_auditor_reads_the_journal_newest_first(
    ui: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(
        repository,
        _event(2, effect=Effect.DENY, rule_id="fs.read.outside"),
        _event(1, source="mcp:jira", tool="create_issue", rule_id=UNCHECKED_SOURCE_RULE),
    )
    _log_in(ui)
    page = ui.get("/journal").text
    assert '<link rel="stylesheet" href="/static/commons.css">' in page
    assert page.index("create_issue") < page.index("fs.read.outside")
    assert '<span class="verdict unchecked">unchecked</span>' in page
    assert '<span class="verdict deny">deny</span>' in page
    assert "Ada Auditor" in page


def test_the_shared_look_is_served(ui: TestClient) -> None:
    assert "--plate: 52px" in ui.get("/static/commons.css").text
    assert ".verdict" in ui.get("/static/audit.css").text


def test_the_journal_narrows_to_the_filter(
    ui: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, _event(2, source="mcp:git", tool="push"), _event(1, source="mcp:jira"))
    _log_in(ui)
    page = ui.get("/journal", params={"source": "mcp:jira"}).text
    assert "mcp:jira" in page
    assert "mcp:git" not in page
    assert 'value="mcp:jira"' in page


def test_an_unknown_effect_is_refused(ui: TestClient) -> None:
    _log_in(ui)
    assert ui.get("/journal", params={"effect": "maybe"}).status_code == 400


def test_moving_between_sections_swaps_the_pane_and_the_rail(ui: TestClient) -> None:
    _log_in(ui)
    fragment = ui.get("/blocks", headers={"HX-Request": "true"}).text
    assert "<html" not in fragment
    assert 'id="main-pane"' in fragment
    assert 'hx-swap-oob="true"' in fragment
    assert 'class="section active" href="/blocks"' in fragment


def test_more_brings_only_the_next_rows(
    ui: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(repository, *(_event(minute) for minute in range(60)))
    _log_in(ui)
    first = ui.get("/journal").text
    assert 'id="more"' in first
    cursor = first.split("cursor=", 1)[1].split('"', 1)[0]
    rows = ui.get(f"/journal?cursor={cursor}", headers={"HX-Request": "true"}).text
    assert "<table" not in rows
    assert "/workspace/59<" not in first
    assert "/workspace/59<" in rows
    assert 'id="more"' not in rows


def test_an_event_shows_everything_it_carries_and_escapes_it(
    ui: TestClient, repository: InMemoryAuditRepository
) -> None:
    written = _event(1, source="mcp:jira", tool="create_issue", content="<script>x()</script>")
    _seed(repository, written)
    _log_in(ui)
    journal = ui.get("/journal").text
    link = journal.split('href="/events?at=', 1)[1].split('"', 1)[0]
    page = ui.get(f"/events?at={link}").text
    assert "create_issue" in page
    assert written.event_id in page
    assert "&lt;script&gt;x()&lt;/script&gt;" in page
    assert "<script>x()" not in page


def test_an_event_that_is_not_there_is_not_found(ui: TestClient) -> None:
    _log_in(ui)
    assert ui.get("/events", params={"at": f"{NOW.isoformat()}|missing"}).status_code == 404


def test_the_auditor_lifts_a_block_and_the_record_says_who(
    ui: TestClient, repository: InMemoryAuditRepository, policy: _Policy
) -> None:
    asyncio.run(repository.block_conversation(CHAT, 31))
    _log_in(ui)
    assert "Lift" in ui.get("/blocks").text
    row = ui.delete(f"/blocks/{CHAT}")
    assert row.status_code == 200
    assert f"by {AUDITOR}" in row.text
    assert policy.lifted == [CHAT]
    assert ui.delete(f"/blocks/{CHAT}").status_code == 404


def test_lifting_needs_the_auditor_role(
    ui: TestClient, repository: InMemoryAuditRepository, policy: _Policy
) -> None:
    asyncio.run(repository.block_conversation(CHAT, 31))
    _log_in(ui, roles="user")
    assert ui.delete(f"/blocks/{CHAT}").status_code == 403
    assert policy.lifted == []


def test_sources_show_what_is_checked_and_what_went_through(
    ui: TestClient, repository: InMemoryAuditRepository
) -> None:
    _seed(
        repository,
        _event(1, source="mcp:jira", rule_id=UNCHECKED_SOURCE_RULE),
        _event(2, source="mcp:jira", rule_id=UNCHECKED_SOURCE_RULE),
        _event(3, source="mcp:git", effect=Effect.DENY),
    )
    _log_in(ui)
    page = ui.get("/sources").text
    jira = page.split("mcp:jira</a>", 1)[1].split("</tr>", 1)[0]
    assert '<span class="verdict unchecked">off</span>' in jira
    assert '<td class="count">2</td>' in jira
    git = page.split("mcp:git</a>", 1)[1].split("</tr>", 1)[0]
    assert "unknown" in git
    assert "opencode" in page


def test_sources_say_so_when_the_policy_service_is_silent(ui: TestClient, policy: _Policy) -> None:
    policy.answering = False
    _log_in(ui)
    assert "did not answer" in ui.get("/sources").text


def test_the_events_of_a_chat_link_from_its_block(
    ui: TestClient, repository: InMemoryAuditRepository
) -> None:
    asyncio.run(repository.block_conversation(CHAT, 31))
    _log_in(ui)
    assert f'href="/journal?conversation={CHAT}"' in ui.get("/blocks").text
