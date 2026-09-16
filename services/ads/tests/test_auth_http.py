from __future__ import annotations

import pytest
from litestar.testing import TestClient

from ads.identity import ACCESS_TOKEN_SESSION_KEY, Identity
from ads.oidc import OidcClient


def test_callback_without_session_is_unauthorized(client: TestClient) -> None:
    response = client.get("/auth/callback", params={"code": "x", "state": "y"})
    assert response.status_code == 401


def test_logout_clears_session(client: TestClient) -> None:
    client.set_session_data(
        {
            "identity": {
                "sub": "alice",
                "name": "Alice",
                "roles": ["user"],
                "email": None,
            }
        }
    )
    response = client.get("/logout", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].endswith("/login")
    page = client.get("/", follow_redirects=False)
    assert page.status_code == 302
    assert page.headers["location"].endswith("/login")


def _alice() -> Identity:
    return Identity(sub="alice", name="Alice", roles=("user",), email="alice@example.com")


def test_callback_without_access_token_is_unauthorized(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exchange_code(self: OidcClient, code: str) -> dict[str, str]:
        del self, code
        return {"id_token": "id-token"}

    def decode_id_token(self: OidcClient, id_token: str, *, nonce: str) -> Identity:
        del self, id_token, nonce
        return _alice()

    monkeypatch.setattr(OidcClient, "exchange_code", exchange_code)
    monkeypatch.setattr(OidcClient, "decode_id_token", decode_id_token)
    client.set_session_data({"oidc_state": "st", "oidc_nonce": "nn"})
    response = client.get(
        "/auth/callback", params={"code": "c", "state": "st"}, follow_redirects=False
    )
    assert response.status_code == 401
    session = client.get_session_data()
    assert "identity" not in session
    assert ACCESS_TOKEN_SESSION_KEY not in session


def test_callback_stores_access_token(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def exchange_code(self: OidcClient, code: str) -> dict[str, str]:
        del self, code
        return {"id_token": "id-token", "access_token": "user-access-token"}

    def decode_id_token(self: OidcClient, id_token: str, *, nonce: str) -> Identity:
        del self, id_token, nonce
        return _alice()

    monkeypatch.setattr(OidcClient, "exchange_code", exchange_code)
    monkeypatch.setattr(OidcClient, "decode_id_token", decode_id_token)
    client.set_session_data({"oidc_state": "st", "oidc_nonce": "nn"})
    response = client.get(
        "/auth/callback", params={"code": "c", "state": "st"}, follow_redirects=False
    )
    assert response.status_code == 302
    session = client.get_session_data()
    assert session[ACCESS_TOKEN_SESSION_KEY] == "user-access-token"
    assert session["identity"]["sub"] == "alice"
