from __future__ import annotations

from litestar.testing import TestClient


def _login(client: TestClient, *, roles: list[str]) -> None:
    client.set_session_data(
        {
            "identity": {
                "sub": "alice",
                "name": "Alice",
                "roles": roles,
                "email": "alice@example.com",
            }
        }
    )


def test_unauthenticated_root_redirects_to_login(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].endswith("/login")


def test_unauthenticated_press_is_unauthorized(client: TestClient) -> None:
    response = client.post("/hello/press", follow_redirects=False)
    assert response.status_code == 401


def test_authenticated_user_sees_hello_world(client: TestClient) -> None:
    _login(client, roles=["user"])
    response = client.get("/")
    assert response.status_code == 200
    assert "hello world" in response.text
    assert "Press" in response.text


def test_authenticated_without_role_still_sees_hello_world(client: TestClient) -> None:
    _login(client, roles=[])
    response = client.get("/")
    assert response.status_code == 200
    assert "hello world" in response.text


def test_press_without_user_role_is_forbidden(client: TestClient) -> None:
    _login(client, roles=[])
    response = client.post("/hello/press", follow_redirects=False)
    assert response.status_code == 403


def test_press_with_user_role_logs_and_flashes(client: TestClient) -> None:
    _login(client, roles=["user"])
    response = client.post("/hello/press", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].endswith("/")
    page = client.get("/")
    assert page.status_code == 200
    assert "button was pressed" in page.text


def test_health_is_public(client: TestClient) -> None:
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").json() == {"status": "ok"}
