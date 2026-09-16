from __future__ import annotations

import uuid

from litestar.testing import TestClient

from tests.threadline_fakes import STORED_BEARER, FakePreferences, login


def test_settings_dialog_never_renders_a_stored_bearer(
    client: TestClient,
    preferences: FakePreferences,
) -> None:
    model = preferences.seed(description="Work chat")
    login(client)
    dialog = client.get("/settings")
    assert dialog.status_code == 200
    assert "Work chat" in dialog.text
    assert STORED_BEARER not in dialog.text
    selected = client.get("/settings", params={"model_id": str(model.id)})
    assert selected.status_code == 200
    assert "gpt-test" in selected.text
    assert "https://llm.example/v1" in selected.text
    assert STORED_BEARER not in selected.text
    assert 'placeholder="Write only. Leave blank to keep."' in selected.text
    assert 'value="openai-stream" readonly' in selected.text
    assert 'name="model-name"' in selected.text


def test_composer_options_never_contain_a_bearer(
    client: TestClient,
    preferences: FakePreferences,
) -> None:
    preferences.seed()
    login(client)
    page = client.get("/")
    assert page.status_code == 200
    assert STORED_BEARER not in page.text


def test_add_model_forwards_the_typed_bearer_once(
    client: TestClient,
    preferences: FakePreferences,
) -> None:
    login(client)
    response = client.post(
        "/settings/models",
        data={
            "description": "Lab vLLM",
            "name": "qwen",
            "model-name": "qwen-api",
            "url": "https://lab.example/v1",
            "bearer": "sk-typed-now",
        },
    )
    assert response.status_code in (200, 201)
    assert "sk-typed-now" not in response.text
    assert "Lab vLLM" in response.text
    assert len(preferences.writes) == 1
    assert preferences.writes[0].authentication.openai_bearer.token == "sk-typed-now"
    assert preferences.writes[0].type == "openai-stream"
    assert preferences.writes[0].name == "qwen"
    assert preferences.writes[0].options.model_name == "qwen-api"


def test_edit_without_a_bearer_patches_without_authentication(
    client: TestClient,
    preferences: FakePreferences,
) -> None:
    model = preferences.seed()
    login(client)
    response = client.patch(
        f"/settings/models/{model.id}",
        data={
            "description": "Renamed",
            "name": "gpt-test",
            "model-name": "gpt-test",
            "url": "https://llm.example/v1",
            "bearer": "",
        },
    )
    assert response.status_code == 200
    assert "Renamed" in response.text
    assert STORED_BEARER not in response.text
    _, patch = preferences.patches[0]
    assert patch.authentication is None
    assert patch.description == "Renamed"
    stored = preferences.models[model.id]
    assert stored.authentication.openai_bearer.token == STORED_BEARER


def test_edit_with_a_bearer_forwards_it(
    client: TestClient,
    preferences: FakePreferences,
) -> None:
    model = preferences.seed()
    login(client)
    response = client.patch(
        f"/settings/models/{model.id}",
        data={"description": "Rotated", "bearer": "sk-rotated"},
    )
    assert response.status_code == 200
    assert "sk-rotated" not in response.text
    _, patch = preferences.patches[0]
    assert patch.authentication is not None
    assert patch.authentication.openai_bearer.token == "sk-rotated"


def test_delete_model_refreshes_the_dialog(
    client: TestClient,
    preferences: FakePreferences,
) -> None:
    model = preferences.seed(description="Doomed")
    login(client)
    response = client.delete(f"/settings/models/{model.id}")
    assert response.status_code == 200
    assert "Doomed" not in response.text
    assert preferences.models == {}


def test_model_writes_require_the_user_role(
    client: TestClient,
    preferences: FakePreferences,
) -> None:
    model = preferences.seed()
    login(client, roles=[])
    assert client.post("/settings/models", data={"description": "x"}).status_code == 403
    assert client.patch(f"/settings/models/{model.id}", data={"name": "y"}).status_code == 403
    assert client.delete(f"/settings/models/{model.id}").status_code == 403


def test_unauthenticated_model_writes_are_401(client: TestClient) -> None:
    assert client.post("/settings/models", data={"description": "x"}).status_code == 401
    assert client.delete(f"/settings/models/{uuid.uuid4()}").status_code == 401


def test_unknown_model_edit_is_404(client: TestClient) -> None:
    login(client)
    response = client.patch(f"/settings/models/{uuid.uuid4()}", data={"name": "x"})
    assert response.status_code == 404
