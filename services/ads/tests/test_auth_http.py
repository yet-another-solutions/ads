from __future__ import annotations

import pytest
from litestar.testing import TestClient
from sqlalchemy.orm import Session

from ads.models import OidcRefreshToken
from ads_commons_web.identity import ACCESS_TOKEN_SESSION_KEY, Identity
from ads_commons_web.oidc import OidcClient
from tests.threadline_fakes import USER_ACCESS_TOKEN, USER_ID


def test_callback_without_session_is_unauthorized(client: TestClient) -> None:
    response = client.get("/auth/callback", params={"code": "x", "state": "y"})
    assert response.status_code == 401


def test_logout_clears_session(client: TestClient) -> None:
    client.set_session_data({ACCESS_TOKEN_SESSION_KEY: USER_ACCESS_TOKEN})
    response = client.get("/logout", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].endswith("/login")
    page = client.get("/", follow_redirects=False)
    assert page.status_code == 302
    assert page.headers["location"].endswith("/login")


def _alice() -> Identity:
    return Identity(sub="alice", name="Alice", roles=("user",), email="alice@example.com")


def _row(client: TestClient, sid: str) -> OidcRefreshToken | None:
    with Session(client.app.state.db_engine) as session:
        return session.get(OidcRefreshToken, sid)


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


def test_callback_without_refresh_token_is_unauthorized(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exchange_code(self: OidcClient, code: str) -> dict[str, str]:
        del self, code
        return {"id_token": "id-token", "access_token": USER_ACCESS_TOKEN}

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
    assert "refresh_token" not in session
    assert _row(client, f"sid-{USER_ID}") is None


def test_callback_stores_access_token(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def exchange_code(self: OidcClient, code: str) -> dict[str, str]:
        del self, code
        return {
            "id_token": "id-token",
            "access_token": USER_ACCESS_TOKEN,
            "refresh_token": "refresh-1",
        }

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
    assert session[ACCESS_TOKEN_SESSION_KEY] == USER_ACCESS_TOKEN
    assert "identity" not in session
    assert "refresh_token" not in session
    row = _row(client, f"sid-{USER_ID}")
    assert row is not None
    assert row.user_id == USER_ID
    assert row.refresh_token == "refresh-1"


def test_logout_deletes_refresh_row(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def exchange_code(self: OidcClient, code: str) -> dict[str, str]:
        del self, code
        return {
            "id_token": "id-token",
            "access_token": USER_ACCESS_TOKEN,
            "refresh_token": "refresh-1",
        }

    def decode_id_token(self: OidcClient, id_token: str, *, nonce: str) -> Identity:
        del self, id_token, nonce
        return _alice()

    monkeypatch.setattr(OidcClient, "exchange_code", exchange_code)
    monkeypatch.setattr(OidcClient, "decode_id_token", decode_id_token)
    client.set_session_data({"oidc_state": "st", "oidc_nonce": "nn"})
    client.get("/auth/callback", params={"code": "c", "state": "st"}, follow_redirects=False)
    assert _row(client, f"sid-{USER_ID}") is not None
    client.get("/logout", follow_redirects=False)
    assert _row(client, f"sid-{USER_ID}") is None
    session = client.get_session_data()
    assert ACCESS_TOKEN_SESSION_KEY not in session
