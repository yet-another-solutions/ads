from __future__ import annotations

from litestar.testing import TestClient


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
