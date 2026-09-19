from __future__ import annotations

import uuid

from litestar.testing import TestClient

from tests.threadline_fakes import FakeAudit, login
from tests.threadline_flows import create_project as _create_project
from tests.threadline_flows import create_session as _create_session

AUDITOR = uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")


def _a_chat(client: TestClient) -> uuid.UUID:
    login(client)
    return _create_session(client, _create_project(client))


def test_an_auditor_sees_whether_a_chat_is_blocked(
    client: TestClient, audit_api: FakeAudit
) -> None:
    chat = _a_chat(client)
    audit_api.block(chat)
    login(client, sub=AUDITOR, roles=["user", "auditor"])
    answer = client.get(f"/auditor/sessions/{chat}/block")
    assert answer.status_code == 200
    assert answer.json()["blocked_at"] is not None


def test_an_auditor_lifts_a_block_and_is_named_as_the_one_who_did(
    client: TestClient, audit_api: FakeAudit
) -> None:
    chat = _a_chat(client)
    audit_api.block(chat)
    login(client, sub=AUDITOR, roles=["user", "auditor"])
    lifted = client.delete(f"/auditor/sessions/{chat}/block")
    assert lifted.status_code == 200
    assert lifted.json()["lifted_by"] == str(AUDITOR)
    assert audit_api.lifted == [(str(chat), str(AUDITOR))]


def test_without_the_auditor_role_a_block_is_none_of_your_business(
    client: TestClient, audit_api: FakeAudit
) -> None:
    chat = _a_chat(client)
    audit_api.block(chat)
    assert client.get(f"/auditor/sessions/{chat}/block").status_code == 403
    assert client.delete(f"/auditor/sessions/{chat}/block").status_code == 403
    assert audit_api.lifted == []


def test_an_auditor_needs_a_chat_that_exists(client: TestClient, audit_api: FakeAudit) -> None:
    login(client, sub=AUDITOR, roles=["user", "auditor"])
    assert client.get(f"/auditor/sessions/{uuid.uuid4()}/block").status_code == 404


def test_lifting_a_block_nobody_placed_is_not_found(
    client: TestClient, audit_api: FakeAudit
) -> None:
    chat = _a_chat(client)
    login(client, sub=AUDITOR, roles=["user", "auditor"])
    assert client.delete(f"/auditor/sessions/{chat}/block").status_code == 404


def test_the_auditor_endpoints_need_a_session(client: TestClient) -> None:
    chat = uuid.uuid4()
    assert client.get(f"/auditor/sessions/{chat}/block").status_code == 401
    assert client.delete(f"/auditor/sessions/{chat}/block").status_code == 401
