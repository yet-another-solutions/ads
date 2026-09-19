from __future__ import annotations

import time
import uuid

from litestar.testing import TestClient

from ads.session_service import AUDITOR_READ_RULE
from ads_policy.audit import CollectingAuditSink
from ads_policy.contract import AuditEvent
from tests.threadline_fakes import FakePreferences, RecordingKafka, login
from tests.threadline_flows import create_project as _create_project
from tests.threadline_flows import create_session as _create_session

AUDITOR = uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")


def _drained(journal: CollectingAuditSink) -> tuple[AuditEvent, ...]:
    """The journal is flushed on a timer, so a reading lands shortly after the read."""
    deadline = time.monotonic() + 5
    while not journal.events() and time.monotonic() < deadline:
        time.sleep(0.01)
    return journal.events()


def test_unauthenticated_shell_redirects_to_login(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].endswith("/login")


def test_unauthenticated_mutating_post_is_401(client: TestClient) -> None:
    response = client.post("/projects", data={"name": "x", "description": "y"})
    assert response.status_code == 401
    session_post = client.post(
        f"/projects/{uuid.uuid4()}/sessions",
        data={"name": "x", "description": "y"},
    )
    assert session_post.status_code == 401


def test_health_is_public(client: TestClient) -> None:
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").json() == {"status": "ok"}


def test_authenticated_shell_renders_threadline(client: TestClient) -> None:
    login(client)
    response = client.get("/")
    assert response.status_code == 200
    assert "<b>ADS</b>" in response.text
    assert "Projects" in response.text
    assert 'id="composer"' in response.text
    assert 'id="session-tree"' in response.text


def test_rail_keeps_plus_and_identity_inside_the_rail(client: TestClient) -> None:
    login(client)
    project = _create_project(client, name="longprojectnamethatmustellipsis")
    _create_session(client, project, name="verylongsessionnamethatmustellipsis")
    page = client.get("/")
    assert page.status_code == 200
    assert 'class="search-box"' in page.text
    search_new = page.text.split('class="icon-plus search-new"', 1)[1].split("</button>", 1)[0]
    assert "hx-get" not in search_new
    assert '<span class="label">longprojectnamethatmustellipsis</span>' in page.text
    assert '<span class="name">verylongsessionnamethatmustellipsis</span>' in page.text
    assert 'id="open-settings"' in page.text
    assert "--plate: 52px" in (client.get("/static/ads.css").text)


def test_shell_is_visible_without_the_user_role(client: TestClient) -> None:
    login(client, roles=[])
    response = client.get("/")
    assert response.status_code == 200
    assert "<b>ADS</b>" in response.text


def test_create_project_without_role_is_403(client: TestClient, kafka: RecordingKafka) -> None:
    login(client, roles=[])
    response = client.post("/projects", data={"name": "P", "description": "D"})
    assert response.status_code == 403
    assert kafka.requests == []


def test_send_without_role_is_403(client: TestClient, kafka: RecordingKafka) -> None:
    login(client)
    project = _create_project(client)
    session_id = _create_session(client, project)
    login(client, roles=[])
    response = client.post(
        f"/projects/{project}/sessions/{session_id}/messages",
        data={"user_input": "hi", "model_id": str(uuid.uuid4())},
    )
    assert response.status_code == 403
    assert kafka.requests == []


def test_composer_has_no_send_button_and_an_empty_first_option(
    client: TestClient,
    preferences: FakePreferences,
) -> None:
    preferences.seed(description="Work chat")
    login(client)
    project = _create_project(client)
    session_id = _create_session(client, project)
    page = client.get(f"/projects/{project}/sessions/{session_id}")
    assert page.status_code == 200
    assert "Work chat" in page.text
    assert '<option value=""></option>' in page.text
    assert 'type="submit"' not in page.text.split('id="composer"')[1]


def test_search_is_a_server_query_and_swaps_the_rail(client: TestClient) -> None:
    login(client)
    project = _create_project(client)
    _create_session(client, project, name="Engine contract")
    _create_session(client, project, name="Memory architecture")
    hit = client.get("/", params={"q": "memory"}, headers={"HX-Request": "true"})
    assert hit.status_code == 200
    assert 'id="session-tree"' in hit.text
    assert "Memory architecture" in hit.text
    assert "Engine contract" not in hit.text
    miss = client.get("/", params={"q": "nothing-here"}, headers={"HX-Request": "true"})
    assert "No session matches" in miss.text
    everything = client.get("/", params={"q": ""}, headers={"HX-Request": "true"})
    assert "Engine contract" in everything.text
    assert "Memory architecture" in everything.text


def test_search_works_while_the_composer_is_disabled(
    client: TestClient,
    preferences: FakePreferences,
    kafka: RecordingKafka,
) -> None:
    model = preferences.seed()
    login(client)
    project = _create_project(client)
    session_id = _create_session(client, project, name="Live session")
    sent = client.post(
        f"/projects/{project}/sessions/{session_id}/messages",
        data={"user_input": "hello", "model_id": str(model.id)},
    )
    assert sent.status_code in (200, 201)
    assert 'data-inflight="true"' in sent.text
    search = client.get("/", params={"q": "live"}, headers={"HX-Request": "true"})
    assert search.status_code == 200
    assert "Live session" in search.text
    assert len(kafka.requests) == 1


def test_dialogs_are_get_only_markup(client: TestClient) -> None:
    login(client)
    project = _create_project(client)
    new_project = client.get("/dialogs/new-project")
    assert new_project.status_code == 200
    assert "<dialog" in new_project.text
    new_session = client.get("/dialogs/new-session")
    assert new_session.status_code == 200
    assert 'name="project_id"' in new_session.text
    fixed = client.get("/dialogs/new-session", params={"project_id": str(project)})
    assert f'value="{project}"' in fixed.text


def test_htmx_navigation_returns_main_pane_and_rail(client: TestClient) -> None:
    login(client)
    project = _create_project(client)
    session_id = _create_session(client, project)
    response = client.get(
        f"/projects/{project}/sessions/{session_id}",
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 200
    assert 'id="main-pane"' in response.text
    assert 'hx-swap-oob="true"' in response.text
    assert "<html" not in response.text


def test_other_users_session_is_403(client: TestClient) -> None:
    login(client)
    project = _create_project(client)
    session_id = _create_session(client, project)
    login(client, sub=uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"))
    response = client.get(f"/projects/{project}/sessions/{session_id}")
    assert response.status_code == 403


def test_an_auditor_reads_another_persons_chat_and_the_reading_is_journalled(
    client: TestClient, journal: CollectingAuditSink
) -> None:
    login(client)
    project = _create_project(client)
    session_id = _create_session(client, project)
    login(client, sub=AUDITOR, roles=["user", "auditor"])
    response = client.get(f"/projects/{project}/sessions/{session_id}")
    assert response.status_code == 200
    (read,) = [event for event in _drained(journal) if event.rule_id == AUDITOR_READ_RULE]
    assert read.subject == str(AUDITOR)
    assert read.resource == str(session_id)
    assert read.conversation == str(session_id)
    assert read.weight == 0


def test_an_auditor_may_not_write_in_another_persons_chat(client: TestClient) -> None:
    login(client)
    project = _create_project(client)
    session_id = _create_session(client, project)
    login(client, sub=AUDITOR, roles=["user", "auditor"])
    response = client.post(
        f"/projects/{project}/sessions/{session_id}/messages",
        data={"user_input": "hello", "model_id": str(uuid.uuid4())},
    )
    assert response.status_code == 403
