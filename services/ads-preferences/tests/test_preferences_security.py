from __future__ import annotations

import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from litestar.testing import TestClient

from ads_commons.security import SecurityContextHolder
from preference_tokens import OTHER_USER_ID, USER_ID, encode_token

MODEL_BODY = {
    "description": "Work chat",
    "name": "gpt-4o",
    "type": "openai-stream",
    "url": "https://example.invalid/v1",
    "authentication": {"openai-bearer": {"token": "sk-secret"}},
    "options": {"model-name": "glm-5.3"},
}


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_is_unauthenticated(client: TestClient) -> None:
    live = client.get("/health/live")
    ready = client.get("/health/ready")
    assert live.status_code == 200
    assert ready.status_code == 200
    assert live.json() == {"status": "ok"}


def test_missing_bearer_is_401_without_bind_or_sql(
    client: TestClient, sql_count: list[int]
) -> None:
    binds: list[object] = []
    original = SecurityContextHolder.set

    def tracking(context: object) -> object:
        binds.append(context)
        return original(context)  # type: ignore[misc]

    SecurityContextHolder.set = tracking  # type: ignore[method-assign]
    try:
        response = client.get("/v1/models")
    finally:
        SecurityContextHolder.set = original  # type: ignore[method-assign]
    assert response.status_code == 401
    assert binds == []
    assert sql_count[0] == 0


def test_garbage_token_is_401(client: TestClient, sql_count: list[int]) -> None:
    response = client.get("/v1/models", headers=_auth("not-a-jwt"))
    assert response.status_code == 401
    assert sql_count[0] == 0


def test_empty_bearer_is_401(client: TestClient) -> None:
    response = client.get("/v1/models", headers={"Authorization": "Bearer "})
    assert response.status_code == 401


def test_wrong_audience_is_401(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    token = encode_token(rsa_key, aud="ads-engine")
    response = client.get("/v1/models", headers=_auth(token))
    assert response.status_code == 401


def test_expired_token_is_401(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    token = encode_token(rsa_key, exp=int(time.time()) - 10)
    response = client.get("/v1/models", headers=_auth(token))
    assert response.status_code == 401


def test_non_uuid_sub_is_401(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    token = encode_token(rsa_key, sub="alice")
    response = client.get("/v1/models", headers=_auth(token))
    assert response.status_code == 401


def test_missing_azp_is_403_without_bind_or_sql(
    client: TestClient, rsa_key: RSAPrivateKey, sql_count: list[int]
) -> None:
    token = encode_token(rsa_key, azp="")
    binds: list[object] = []
    original = SecurityContextHolder.set

    def tracking(context: object) -> object:
        binds.append(context)
        return original(context)  # type: ignore[misc]

    SecurityContextHolder.set = tracking  # type: ignore[method-assign]
    try:
        response = client.get("/v1/models", headers=_auth(token))
    finally:
        SecurityContextHolder.set = original  # type: ignore[method-assign]
    assert response.status_code == 403
    assert binds == []
    assert sql_count[0] == 0


def test_other_azp_is_403(client: TestClient, rsa_key: RSAPrivateKey, sql_count: list[int]) -> None:
    token = encode_token(rsa_key, azp="ads-engine")
    response = client.get("/v1/models", headers=_auth(token))
    assert response.status_code == 403
    assert sql_count[0] == 0


def test_missing_user_role_is_403(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    token = encode_token(rsa_key, realm_access={"roles": []})
    response = client.get("/v1/models", headers=_auth(token))
    assert response.status_code == 403


def test_allowed_caller_with_user_role_lists(client: TestClient, user_token: str) -> None:
    response = client.get("/v1/models", headers=_auth(user_token))
    assert response.status_code == 200
    assert response.json() == {"models": []}


def test_cross_user_id_is_404_not_403(
    client: TestClient, rsa_key: RSAPrivateKey, user_token: str
) -> None:
    created = client.post("/v1/models", json=MODEL_BODY, headers=_auth(user_token))
    assert created.status_code == 201
    model_id = created.json()["id"]
    other = encode_token(rsa_key, sub=str(OTHER_USER_ID))
    info = client.get(f"/v1/models/{model_id}", headers=_auth(other))
    patched = client.patch(
        f"/v1/models/{model_id}",
        json={"description": "stolen"},
        headers=_auth(other),
    )
    deleted = client.delete(f"/v1/models/{model_id}", headers=_auth(other))
    assert info.status_code == 404
    assert patched.status_code == 404
    assert deleted.status_code == 404
    still = client.get(f"/v1/models/{model_id}", headers=_auth(user_token))
    assert still.status_code == 200
    assert still.json()["id"] == model_id
    assert USER_ID.hex


def test_unknown_id_is_404(client: TestClient, user_token: str) -> None:
    missing = str(uuid4())
    assert client.get(f"/v1/models/{missing}", headers=_auth(user_token)).status_code == 404
    assert (
        client.patch(
            f"/v1/models/{missing}",
            json={"description": "x"},
            headers=_auth(user_token),
        ).status_code
        == 404
    )
    assert client.delete(f"/v1/models/{missing}", headers=_auth(user_token)).status_code == 404


def test_malformed_id_is_400(client: TestClient, user_token: str) -> None:
    response = client.get("/v1/models/not-a-uuid", headers=_auth(user_token))
    assert response.status_code == 400
