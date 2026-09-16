"""HTTP flow helpers: create a project, a session, and send a turn like the browser does."""

from __future__ import annotations

import re
import uuid

from litestar.testing import TestClient

_PROJECT = re.compile(r'data-project-id="([0-9a-f-]{36})"')


def create_project(client: TestClient, name: str = "Harness design") -> uuid.UUID:
    response = client.post("/projects", data={"name": name, "description": f"{name} description"})
    assert response.status_code in (200, 201), response.text
    found = _PROJECT.findall(response.text)
    assert found, response.text
    return uuid.UUID(found[-1])


def create_session(
    client: TestClient,
    project_id: uuid.UUID,
    name: str = "UI concepts",
) -> uuid.UUID:
    response = client.post(
        f"/projects/{project_id}/sessions",
        data={"name": name, "description": f"{name} description"},
    )
    assert response.status_code in (200, 201), response.text
    return uuid.UUID(response.headers["HX-Push-Url"].rsplit("/", 1)[1])


def send(
    client: TestClient,
    project_id: uuid.UUID,
    session_id: uuid.UUID,
    text: str,
    model_id: uuid.UUID | str | None,
) -> object:
    payload = {"user_input": text}
    if model_id is not None:
        payload["model_id"] = str(model_id)
    return client.post(f"/projects/{project_id}/sessions/{session_id}/messages", data=payload)


def project_ids(text: str) -> list[uuid.UUID]:
    return [uuid.UUID(value) for value in _PROJECT.findall(text)]
