from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock

import msgspec
import pytest
from litestar.testing import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from ads.exceptions import InvalidInput
from ads.models import Project
from ads.preferences_client import PreferencesUnavailable
from ads.project_service import ProjectService
from ads.repository import ProjectRepository, SessionRepository, SessionRunRepository
from ads_commons.egress import ProjectEgressSettings, ProjectEgressSnapshot
from ads_commons.security import SecurityContext, SecurityContextHolder
from tests.threadline_fakes import USER_ID, FakePreferences, RecordingEgress, login


def service(session: Session, preferences: FakePreferences) -> ProjectService:
    return ProjectService(
        session,
        ProjectRepository(session),
        SessionRepository(session),
        SessionRunRepository(session),
        preferences,
        RecordingEgress(),
    )


def context() -> SecurityContext:
    return SecurityContext(subject=str(USER_ID), name="Alice", roles=frozenset({"user"}))


@pytest.mark.parametrize("failure", ["before", "lost_response", "database", "bad_snapshot"])
def test_create_failure_never_exposes_project(
    db_engine: Engine, preferences: FakePreferences, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    original = preferences.save_egress

    async def save(project_id: uuid.UUID, settings: ProjectEgressSettings) -> ProjectEgressSnapshot:
        if failure == "before":
            raise PreferencesUnavailable()
        result = await original(project_id, settings)
        if failure == "lost_response":
            raise PreferencesUnavailable()
        if failure == "bad_snapshot":
            return ProjectEgressSnapshot(revision=2, settings=settings)
        return result

    monkeypatch.setattr(preferences, "save_egress", save)
    if failure == "database":
        monkeypatch.setattr(
            ProjectRepository,
            "insert",
            lambda *_: (_ for _ in ()).throw(RuntimeError("database failed")),
        )
    delete = AsyncMock(wraps=preferences.delete_egress)
    monkeypatch.setattr(preferences, "delete_egress", delete)
    with Session(db_engine) as session, SecurityContextHolder.bound(context()):
        with pytest.raises((PreferencesUnavailable, RuntimeError, InvalidInput)):
            asyncio.run(service(session, preferences).create("P", "D"))
        assert list(session.scalars(select(Project))) == []
    delete.assert_awaited_once()
    assert preferences.egress == {}


def test_cleanup_failure_does_not_expose_project(
    db_engine: Engine, preferences: FakePreferences, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preferences, "save_egress", AsyncMock(side_effect=PreferencesUnavailable()))
    monkeypatch.setattr(
        preferences, "delete_egress", AsyncMock(side_effect=PreferencesUnavailable())
    )
    with Session(db_engine) as session, SecurityContextHolder.bound(context()):
        with pytest.raises(PreferencesUnavailable):
            asyncio.run(service(session, preferences).create("P", "D"))
        assert list(session.scalars(select(Project))) == []


def create_project(client: TestClient, preferences: FakePreferences) -> uuid.UUID:
    login(client)
    assert client.post("/projects", data={"name": "Private", "description": "D"}).status_code == 200
    return next(iter(preferences.egress))


def test_create_and_edit_only_owned_project(
    client: TestClient, preferences: FakePreferences
) -> None:
    project_id = create_project(client, preferences)
    assert preferences.egress[project_id] == ProjectEgressSnapshot(
        revision=1, settings=ProjectEgressSettings(rules=())
    )
    path = f"/projects/{project_id}/egress-settings"
    response = client.get(f"/dialogs/project-egress/{project_id}")
    assert response.status_code == 200
    assert "Whitelist" in response.text and "Revision 1" in response.text
    settings = {"mode": "blacklist", "rules": []}
    response = client.post(path, data={"settings": msgspec.json.encode(settings).decode()})
    assert response.status_code == 200
    assert "Revision 2" in response.text and "Settings saved" in response.text
    assert preferences.egress[project_id].settings.mode == "blacklist"
    login(client, sub=uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), roles=["user"])
    assert client.get(f"/dialogs/project-egress/{project_id}").status_code == 404
    assert client.post(path, data={"settings": '{"rules":[]}'}).status_code == 404
    assert preferences.egress[project_id].revision == 2


@pytest.mark.parametrize(
    "payload",
    [
        '{"rules":null}',
        '{"mode":null,"rules":[]}',
        '{"rules":[{"domain":"*","port":443,'
        '"protocol":"https","protocol_settings":{"upgrades":"any"}}]}',
        "{}",
        "not-json",
    ],
)
def test_invalid_settings_do_not_persist(
    client: TestClient, preferences: FakePreferences, payload: str
) -> None:
    project_id = create_project(client, preferences)
    assert (
        client.post(
            f"/projects/{project_id}/egress-settings", data={"settings": payload}
        ).status_code
        == 400
    )
    assert preferences.egress[project_id].revision == 1


def test_settings_route_security(client: TestClient, preferences: FakePreferences) -> None:
    project_id = create_project(client, preferences)
    path = f"/projects/{project_id}/egress-settings"
    login(client, roles=["other"])
    assert client.get(f"/dialogs/project-egress/{project_id}").status_code == 403
    assert client.post(path, data={"settings": '{"rules":[]}'}).status_code == 403
    client.cookies.clear()
    assert (
        client.get(f"/dialogs/project-egress/{project_id}", follow_redirects=False).status_code
        == 302
    )
    assert client.post(path, data={"settings": '{"rules":[]}'}).status_code == 401
