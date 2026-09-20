from __future__ import annotations

import uuid

import pytest
from litestar import Litestar
from litestar.testing import TestClient

from ads_commons.engine import AssistantMessage, Finish, PartialResponse
from tests.threadline_db import emit
from tests.threadline_fakes import STORED_BEARER, FakePreferences, login
from tests.threadline_flows import create_project, create_session, send


@pytest.mark.parametrize("htmx", [False, True])
def test_session_remembers_latest_model_across_refresh_and_reopen(
    client: TestClient, app: Litestar, preferences: FakePreferences, htmx: bool
) -> None:
    first, second = preferences.seed("First"), preferences.seed("Second")
    login(client)
    project = create_project(client)
    session = create_session(client, project)
    other = create_session(client, project)
    path = f"/projects/{project}/sessions/{session}"
    headers = {"HX-Request": "true"} if htmx else {}

    assert " selected" not in client.get(path, headers=headers).text.split('id="composer"')[1]
    for model in (first, second):
        response = send(client, project, session, "remember my model", model.id)
        assert response.status_code == 200
        # The active run and the finished run both restore the model server-side.
        for finished in (False, True):
            if finished:
                emit(
                    app,
                    PartialResponse(
                        session_id=session, order=0, message=AssistantMessage(text="done")
                    ),
                )
                emit(app, Finish(session_id=session, last_order=0))
            page = client.get(path, headers=headers)
            assert f'value="{model.id}" selected' in page.text
            assert STORED_BEARER not in page.text
        other_page = client.get(f"/projects/{project}/sessions/{other}", headers=headers)
        assert f'value="{model.id}" selected' not in other_page.text
        assert f'value="{model.id}" selected' in client.get(path, headers=headers).text

    # A removed/unavailable model never silently switches the user to another model.
    del preferences.models[second.id]
    page = client.get(path, headers=headers)
    assert f'value="{second.id}"' not in page.text
    assert f'value="{first.id}" selected' not in page.text


def test_model_selection_does_not_leak_through_session_ownership(
    client: TestClient, preferences: FakePreferences
) -> None:
    model = preferences.seed()
    login(client)
    project = create_project(client)
    session = create_session(client, project)
    send(client, project, session, "hello", model.id)
    login(client, sub=uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"))
    response = client.get(f"/projects/{project}/sessions/{session}")
    assert response.status_code == 403
    assert str(model.id) not in response.text
