from __future__ import annotations

import time
import uuid
from typing import Any

from litestar.testing import TestClient

from ads.session_service import AUDITOR_READ_RULE
from ads_policy.audit import CollectingAuditSink
from ads_policy.contract import AuditEvent
from tests.threadline_fakes import (
    AUDITOR_ID,
    AUDITOR_TOKEN,
    ENGINE_TOKEN,
    NOT_AN_AUDITOR_TOKEN,
    login,
)
from tests.threadline_flows import create_project as _create_project
from tests.threadline_flows import create_session as _create_session


def _drained(journal: CollectingAuditSink) -> tuple[AuditEvent, ...]:
    """The journal is flushed on a timer, so a reading lands shortly after the read."""
    deadline = time.monotonic() + 5
    while not journal.events() and time.monotonic() < deadline:
        time.sleep(0.01)
    return journal.events()


def _a_chat(client: TestClient) -> uuid.UUID:
    login(client)
    chat = _create_session(client, _create_project(client))
    client.cookies.clear()
    return chat


def _read(client: TestClient, chat: uuid.UUID, token: str | None = AUDITOR_TOKEN) -> Any:
    headers = {} if token is None else {"authorization": f"Bearer {token}"}
    return client.get(f"/auditor/sessions/{chat}/transcript", headers=headers)


def test_an_auditor_reads_another_persons_chat_and_the_reading_is_journalled(
    client: TestClient, journal: CollectingAuditSink
) -> None:
    chat = _a_chat(client)
    response = _read(client, chat)
    assert response.status_code == 200
    assert response.json()["session"]["id"] == str(chat)
    (read,) = [event for event in _drained(journal) if event.rule_id == AUDITOR_READ_RULE]
    assert read.subject == str(AUDITOR_ID)
    assert read.resource == str(chat)
    assert read.conversation == str(chat)
    assert read.weight == 0


def test_the_transcript_needs_a_bearer(client: TestClient) -> None:
    assert _read(client, _a_chat(client), token=None).status_code == 401


def test_only_the_auditors_pages_may_ask(client: TestClient) -> None:
    assert _read(client, _a_chat(client), token=ENGINE_TOKEN).status_code == 403


def test_the_transcript_needs_the_auditor_role(client: TestClient) -> None:
    assert _read(client, _a_chat(client), token=NOT_AN_AUDITOR_TOKEN).status_code == 403


def test_an_auditor_needs_a_chat_that_exists(client: TestClient) -> None:
    assert _read(client, uuid.uuid4()).status_code == 404
