from __future__ import annotations

import re
import shutil
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
import uvicorn

from ads.app import create_app
from ads.config import Settings

docker_ok = shutil.which("docker") is not None
pytestmark = pytest.mark.skipif(not docker_ok, reason="docker required for Keycloak testcontainers")

KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.2"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin"
REALM = "ads"
CLIENT_ID = "ads"
CLIENT_SECRET = "ads-test-secret"
USER_NAME = "alice"
USER_PASSWORD = "alice-pass"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _tag_attrs(tag: str) -> dict[str, str]:
    return {key.lower(): value for key, value in re.findall(r'([a-zA-Z0-9:_-]+)="([^"]*)"', tag)}


def _html_form(html: str, form_id: str) -> tuple[str, dict[str, str]]:
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, flags=re.IGNORECASE | re.DOTALL):
        attrs = _tag_attrs(match.group(1))
        if attrs.get("id") != form_id:
            continue
        action = attrs.get("action", "").replace("&amp;", "&")
        fields: dict[str, str] = {}
        for tag in re.finditer(
            r"<(?:input|button)\b([^>]*)/?>", match.group(2), flags=re.IGNORECASE
        ):
            tag_attrs = _tag_attrs(tag.group(1))
            name = tag_attrs.get("name")
            if name:
                fields[name] = tag_attrs.get("value", "")
        return action, fields
    raise AssertionError(f"form {form_id} not found")


@pytest.fixture(scope="module")
def keycloak_base() -> Iterator[str]:
    pytest.importorskip("testcontainers")
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.wait_strategies import LogMessageWaitStrategy

    container = (
        DockerContainer(KEYCLOAK_IMAGE)
        .with_exposed_ports(8080)
        .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
        .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .with_env("KC_HTTP_ENABLED", "true")
        .with_env("KC_HOSTNAME_STRICT", "false")
        .with_command("start-dev")
        .waiting_for(LogMessageWaitStrategy("Listening on").with_startup_timeout(180))
    )
    with container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(8080)
        yield f"http://{host}:{port}"


def _admin_token(base: str) -> str:
    response = httpx.post(
        f"{base}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
        },
        timeout=30.0,
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


def _provision_realm(base: str, redirect_uri: str) -> None:
    token = _admin_token(base)
    headers = {"Authorization": f"Bearer {token}"}
    create = httpx.post(
        f"{base}/admin/realms",
        headers=headers,
        json={"realm": REALM, "enabled": True},
        timeout=30.0,
    )
    if create.status_code not in {201, 409}:
        create.raise_for_status()
    httpx.post(
        f"{base}/admin/realms/{REALM}/roles",
        headers=headers,
        json={"name": "user"},
        timeout=30.0,
    ).raise_for_status()
    client_resp = httpx.post(
        f"{base}/admin/realms/{REALM}/clients",
        headers=headers,
        json={
            "clientId": CLIENT_ID,
            "secret": CLIENT_SECRET,
            "enabled": True,
            "publicClient": False,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": [redirect_uri],
            "webOrigins": ["+"],
            "protocol": "openid-connect",
            "attributes": {"pkce.code.challenge.method": ""},
            "protocolMappers": [
                {
                    "name": "aud-ads",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                        "included.client.audience": CLIENT_ID,
                        "id.token.claim": "true",
                        "access.token.claim": "true",
                    },
                },
                {
                    "name": "realm-roles",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-realm-role-mapper",
                    "config": {
                        "multivalued": "true",
                        "userinfo.token.claim": "true",
                        "id.token.claim": "true",
                        "access.token.claim": "true",
                        "claim.name": "realm_access.roles",
                        "jsonType.label": "String",
                    },
                },
            ],
        },
        timeout=30.0,
    )
    if client_resp.status_code not in {201, 409}:
        client_resp.raise_for_status()
    user_resp = httpx.post(
        f"{base}/admin/realms/{REALM}/users",
        headers=headers,
        json={
            "username": USER_NAME,
            "enabled": True,
            "email": "alice@example.com",
            "emailVerified": True,
            "firstName": "Alice",
            "lastName": "User",
            "credentials": [{"type": "password", "value": USER_PASSWORD, "temporary": False}],
        },
        timeout=30.0,
    )
    if user_resp.status_code not in {201, 409}:
        user_resp.raise_for_status()
    users = httpx.get(
        f"{base}/admin/realms/{REALM}/users",
        headers=headers,
        params={"username": USER_NAME},
        timeout=30.0,
    )
    users.raise_for_status()
    user_id = users.json()[0]["id"]
    role = httpx.get(
        f"{base}/admin/realms/{REALM}/roles/user",
        headers=headers,
        timeout=30.0,
    )
    role.raise_for_status()
    mapping = httpx.post(
        f"{base}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
        headers=headers,
        json=[role.json()],
        timeout=30.0,
    )
    if mapping.status_code not in {204, 409}:
        mapping.raise_for_status()


@pytest.fixture(scope="module")
def running_app(keycloak_base: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    app_port = _free_port()
    public_base = f"http://127.0.0.1:{app_port}"
    _provision_realm(keycloak_base, f"{public_base}/auth/callback")
    data_dir = tmp_path_factory.mktemp("data")
    settings = Settings(
        keycloak_well_known_url=f"{keycloak_base}/realms/{REALM}/.well-known/openid-configuration",
        keycloak_issuer=f"{keycloak_base}/realms/{REALM}",
        keycloak_client_id=CLIENT_ID,
        keycloak_client_secret=CLIENT_SECRET,
        keycloak_audience=CLIENT_ID,
        keycloak_role="user",
        session_secret="integration-session-secret!",
        public_base_url=public_base,
        data_dir=Path(data_dir),
        tls_enabled=False,
        tls_cert_path=None,
        tls_key_path=None,
        bind_host="127.0.0.1",
        port=app_port,
    )
    server = uvicorn.Server(
        uvicorn.Config(create_app(settings), host="127.0.0.1", port=app_port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            httpx.get(f"{public_base}/health/live", timeout=0.2).raise_for_status()
            break
        except httpx.HTTPError:
            thread.join(timeout=0.1)
    else:
        raise RuntimeError("app did not start")
    try:
        yield public_base
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.mark.integration
def test_keycloak_login_hello_world_and_button(running_app: str) -> None:
    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        page = client.get(running_app + "/")
        assert page.status_code == 200
        action, fields = _html_form(page.text, "kc-form-login")
        fields["username"] = USER_NAME
        fields["password"] = USER_PASSWORD
        fields["login"] = fields.get("login") or "Sign In"
        origin = f"{urlsplit(str(page.url)).scheme}://{urlsplit(str(page.url)).netloc}"
        hello = client.post(
            action,
            data=fields,
            headers={"Origin": origin, "Referer": str(page.url)},
        )
        assert hello.status_code == 200
        assert "hello world" in hello.text
        pressed = client.post(running_app + "/hello/press", follow_redirects=True)
        assert pressed.status_code == 200
        assert "button was pressed" in pressed.text
