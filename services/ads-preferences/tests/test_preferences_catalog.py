from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from litestar.testing import TestClient

from preference_tokens import OTHER_USER_ID, encode_token

MODEL_BODY = {
    "description": "Work chat",
    "name": "gpt-4o",
    "type": "openai-stream",
    "url": "https://example.invalid/v1",
    "authentication": {"openai-bearer": {"token": "sk-secret"}},
}


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_empty_catalog_is_200_wrapper(client: TestClient, user_token: str) -> None:
    response = client.get("/v1/models", headers=_auth(user_token))
    assert response.status_code == 200
    assert response.json() == {"models": []}


def test_list_is_summary_only_sorted_by_name_then_id(client: TestClient, user_token: str) -> None:
    first = {
        **MODEL_BODY,
        "description": "Zed",
        "name": "beta",
        "authentication": {"openai-bearer": {"token": "sk-one"}},
    }
    second = {
        **MODEL_BODY,
        "description": "Alpha",
        "name": "alpha",
        "authentication": {"openai-bearer": {"token": "sk-two"}},
    }
    third = {
        **MODEL_BODY,
        "description": "Same name later",
        "name": "alpha",
        "authentication": {"openai-bearer": {"token": "sk-three"}},
    }
    created = [
        client.post("/v1/models", json=body, headers=_auth(user_token)).json()
        for body in (first, second, third)
    ]
    listing = client.get("/v1/models", headers=_auth(user_token))
    assert listing.status_code == 200
    models = listing.json()["models"]
    assert models[-1]["description"] == "Zed"
    alphas = models[:-1]
    alpha_ids = sorted(item["id"] for item in created if item["name"] == "alpha")
    assert [item["id"] for item in alphas] == alpha_ids
    assert {item["description"] for item in alphas} == {"Alpha", "Same name later"}
    for item in models:
        assert set(item) == {"id", "description"}
        assert "authentication" not in item
        assert "url" not in item
        assert "name" not in item
        assert "sk-" not in listing.text


def test_info_returns_invoke_fields_and_bearer(client: TestClient, user_token: str) -> None:
    created = client.post("/v1/models", json=MODEL_BODY, headers=_auth(user_token))
    assert created.status_code == 201
    model_id = created.json()["id"]
    assert created.headers["location"] == f"/v1/models/{model_id}"
    info = client.get(f"/v1/models/{model_id}", headers=_auth(user_token))
    assert info.status_code == 200
    payload = info.json()
    assert payload["id"] == model_id
    assert payload["description"] == "Work chat"
    assert payload["name"] == "gpt-4o"
    assert payload["type"] == "openai-stream"
    assert payload["url"] == "https://example.invalid/v1"
    assert payload["authentication"] == {"openai-bearer": {"token": "sk-secret"}}


def test_post_rejects_id_user_id_and_wrong_type(client: TestClient, user_token: str) -> None:
    with_id = {**MODEL_BODY, "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}
    with_user = {**MODEL_BODY, "user_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
    wrong_type = {**MODEL_BODY, "type": "openai-rest"}
    assert client.post("/v1/models", json=with_id, headers=_auth(user_token)).status_code == 400
    assert client.post("/v1/models", json=with_user, headers=_auth(user_token)).status_code == 400
    assert client.post("/v1/models", json=wrong_type, headers=_auth(user_token)).status_code == 400
    listing = client.get("/v1/models", headers=_auth(user_token))
    assert listing.json() == {"models": []}


def test_post_rejects_empty_fields(client: TestClient, user_token: str) -> None:
    empty_name = {**MODEL_BODY, "name": "  "}
    empty_token = {
        **MODEL_BODY,
        "authentication": {"openai-bearer": {"token": ""}},
    }
    assert client.post("/v1/models", json=empty_name, headers=_auth(user_token)).status_code == 400
    assert client.post("/v1/models", json=empty_token, headers=_auth(user_token)).status_code == 400


def test_patch_label_keeps_bearer_and_auth_replaces(client: TestClient, user_token: str) -> None:
    created = client.post("/v1/models", json=MODEL_BODY, headers=_auth(user_token))
    model_id = created.json()["id"]
    labeled = client.patch(
        f"/v1/models/{model_id}",
        json={"description": "Home chat"},
        headers=_auth(user_token),
    )
    assert labeled.status_code == 200
    assert labeled.json()["description"] == "Home chat"
    assert labeled.json()["authentication"]["openai-bearer"]["token"] == "sk-secret"
    rotated = client.patch(
        f"/v1/models/{model_id}",
        json={
            "url": "https://example.invalid/v2",
            "authentication": {"openai-bearer": {"token": "sk-new"}},
        },
        headers=_auth(user_token),
    )
    assert rotated.status_code == 200
    assert rotated.json()["url"] == "https://example.invalid/v2"
    assert rotated.json()["authentication"]["openai-bearer"]["token"] == "sk-new"


def test_empty_patch_is_400(client: TestClient, user_token: str) -> None:
    created = client.post("/v1/models", json=MODEL_BODY, headers=_auth(user_token))
    model_id = created.json()["id"]
    response = client.patch(f"/v1/models/{model_id}", json={}, headers=_auth(user_token))
    assert response.status_code == 400


def test_delete_then_get_is_404(client: TestClient, user_token: str) -> None:
    created = client.post("/v1/models", json=MODEL_BODY, headers=_auth(user_token))
    model_id = created.json()["id"]
    deleted = client.delete(f"/v1/models/{model_id}", headers=_auth(user_token))
    assert deleted.status_code == 204
    assert deleted.text == ""
    assert client.get(f"/v1/models/{model_id}", headers=_auth(user_token)).status_code == 404
    assert client.delete(f"/v1/models/{model_id}", headers=_auth(user_token)).status_code == 404


def test_per_user_filtering(client: TestClient, rsa_key: RSAPrivateKey, user_token: str) -> None:
    mine = client.post("/v1/models", json=MODEL_BODY, headers=_auth(user_token))
    other = encode_token(rsa_key, sub=str(OTHER_USER_ID))
    theirs_body = {**MODEL_BODY, "description": "Other chat", "name": "other-model"}
    theirs = client.post("/v1/models", json=theirs_body, headers=_auth(other))
    assert mine.status_code == 201
    assert theirs.status_code == 201
    mine_list = client.get("/v1/models", headers=_auth(user_token)).json()["models"]
    theirs_list = client.get("/v1/models", headers=_auth(other)).json()["models"]
    assert [item["id"] for item in mine_list] == [mine.json()["id"]]
    assert [item["id"] for item in theirs_list] == [theirs.json()["id"]]


def test_put_is_405(client: TestClient, user_token: str) -> None:
    created = client.post("/v1/models", json=MODEL_BODY, headers=_auth(user_token))
    model_id = created.json()["id"]
    response = client.put(f"/v1/models/{model_id}", json=MODEL_BODY, headers=_auth(user_token))
    assert response.status_code == 405


def test_list_and_logs_omit_bearer(client: TestClient, user_token: str, capsys: object) -> None:
    created = client.post("/v1/models", json=MODEL_BODY, headers=_auth(user_token))
    listing = client.get("/v1/models", headers=_auth(user_token))
    assert "sk-secret" not in listing.text
    assert created.json()["authentication"]["openai-bearer"]["token"] == "sk-secret"
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "sk-secret" not in captured.out
    assert "sk-secret" not in captured.err
