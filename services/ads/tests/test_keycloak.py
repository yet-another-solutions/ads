from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx2
import pytest
import uvicorn

from ads.app import create_app, create_schema
from ads.config import Settings
from ads.db import create_db_engine
from tests.certs import issue_tls, openssl_available

docker_ok = shutil.which("docker") is not None
pytestmark = pytest.mark.skipif(
    not docker_ok or not openssl_available(),
    reason="docker and openssl required for Keycloak TLS testcontainers",
)

KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.2"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin"
REALM = "ads"
CLIENT_ID = "ads"
CLIENT_SECRET = "ads-test-secret"
USER_NAME = "alice"
USER_PASSWORD = "alice-pass"


@dataclass(frozen=True)
class KeycloakTls:
    base: str
    ca_crt: Path
    server_crt: Path
    server_key: Path


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _ca_context(ca_crt: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(ca_crt))


def _http_client(*, verify: ssl.SSLContext) -> httpx2.Client:
    return httpx2.Client(
        follow_redirects=True,
        timeout=30.0,
        verify=verify,
        headers={"User-Agent": "Mozilla/5.0 ads-integration-test"},
    )


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
def keycloak_tls(tmp_path_factory: pytest.TempPathFactory) -> Iterator[KeycloakTls]:
    pytest.importorskip("testcontainers")
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.wait_strategies import LogMessageWaitStrategy

    cert_dir = tmp_path_factory.mktemp("kc-certs")
    ca_crt, server_crt, server_key = issue_tls(cert_dir)
    previous = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = str(ca_crt)
    container = (
        DockerContainer(KEYCLOAK_IMAGE)
        .with_exposed_ports(8443)
        .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
        .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .with_env("KC_HOSTNAME_STRICT", "false")
        .with_copy_into_container(server_crt, "tmp/tls.crt")
        .with_copy_into_container(server_key, "tmp/tls.key")
        .with_command(
            [
                "start-dev",
                "--https-certificate-file=/tmp/tls.crt",
                "--https-certificate-key-file=/tmp/tls.key",
            ]
        )
        .waiting_for(LogMessageWaitStrategy("Listening on").with_startup_timeout(180))
    )

    def _logs() -> str:
        try:
            stdout, stderr = container.get_logs()
            return f"stdout={stdout.decode()[-3000:]}\nstderr={stderr.decode()[-3000:]}"
        except Exception as log_exc:
            return f"logs unavailable: {log_exc}"

    try:
        try:
            container.start()
        except Exception as exc:
            raise RuntimeError(f"keycloak failed: {exc}\n{_logs()}") from exc
        host = container.get_container_host_ip()
        if host in {"localhost", "0.0.0.0"}:
            host = "127.0.0.1"
        port = container.get_exposed_port(8443)
        yield KeycloakTls(
            base=f"https://{host}:{port}",
            ca_crt=ca_crt,
            server_crt=server_crt,
            server_key=server_key,
        )
    finally:
        try:
            container.stop()
        except Exception:
            pass
        if previous is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = previous


def _admin_token(base: str, verify: ssl.SSLContext) -> str:
    response = httpx2.post(
        f"{base}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
        },
        timeout=30.0,
        verify=verify,
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


def _provision_realm(base: str, redirect_uri: str, verify: ssl.SSLContext) -> None:
    token = _admin_token(base, verify)
    headers = {"Authorization": f"Bearer {token}"}
    create = httpx2.post(
        f"{base}/admin/realms",
        headers=headers,
        json={"realm": REALM, "enabled": True, "sslRequired": "none"},
        timeout=30.0,
        verify=verify,
    )
    if create.status_code not in {201, 409}:
        create.raise_for_status()
    httpx2.post(
        f"{base}/admin/realms/{REALM}/roles",
        headers=headers,
        json={"name": "user"},
        timeout=30.0,
        verify=verify,
    ).raise_for_status()
    client_resp = httpx2.post(
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
        verify=verify,
    )
    if client_resp.status_code not in {201, 409}:
        client_resp.raise_for_status()
    user_resp = httpx2.post(
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
        verify=verify,
    )
    if user_resp.status_code not in {201, 409}:
        user_resp.raise_for_status()
    users = httpx2.get(
        f"{base}/admin/realms/{REALM}/users",
        headers=headers,
        params={"username": USER_NAME},
        timeout=30.0,
        verify=verify,
    )
    users.raise_for_status()
    user_id = users.json()[0]["id"]
    role = httpx2.get(
        f"{base}/admin/realms/{REALM}/roles/user",
        headers=headers,
        timeout=30.0,
        verify=verify,
    )
    role.raise_for_status()
    mapping = httpx2.post(
        f"{base}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
        headers=headers,
        json=[role.json()],
        timeout=30.0,
        verify=verify,
    )
    if mapping.status_code not in {204, 409}:
        mapping.raise_for_status()


@pytest.fixture(scope="module")
def running_app(
    keycloak_tls: KeycloakTls, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[str]:
    app_port = _free_port()
    public_base = f"https://127.0.0.1:{app_port}"
    verify = _ca_context(keycloak_tls.ca_crt)
    _provision_realm(keycloak_tls.base, f"{public_base}/auth/callback", verify)
    data_dir = tmp_path_factory.mktemp("data")
    settings = Settings(
        keycloak_well_known_url=f"{keycloak_tls.base}/realms/{REALM}/.well-known/openid-configuration",
        keycloak_issuer=f"{keycloak_tls.base}/realms/{REALM}",
        keycloak_client_id=CLIENT_ID,
        keycloak_client_secret=CLIENT_SECRET,
        keycloak_audience=CLIENT_ID,
        keycloak_role="user",
        session_secret="integration-session-secret!",
        public_base_url=public_base,
        data_dir=Path(data_dir),
        tls_cert_path=keycloak_tls.server_crt,
        tls_key_path=keycloak_tls.server_key,
        tls_ca_bundle=keycloak_tls.ca_crt,
        bind_host="127.0.0.1",
        port=app_port,
    )
    db_engine = create_db_engine(settings.database_url)
    create_schema(db_engine)
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(settings, engine=db_engine),
            host="127.0.0.1",
            port=app_port,
            ssl_certfile=str(keycloak_tls.server_crt),
            ssl_keyfile=str(keycloak_tls.server_key),
            log_level="warning",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            httpx2.get(f"{public_base}/health/live", timeout=0.2, verify=verify).raise_for_status()
            break
        except httpx2.HTTPError:
            thread.join(timeout=0.1)
    else:
        raise RuntimeError("app did not start")
    try:
        yield public_base
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.mark.integration
def test_keycloak_login_shows_the_threadline_shell(
    running_app: str, keycloak_tls: KeycloakTls
) -> None:
    with _http_client(verify=_ca_context(keycloak_tls.ca_crt)) as client:
        page = client.get(running_app + "/")
        assert page.status_code == 200
        action, fields = _html_form(page.text, "kc-form-login")
        fields["username"] = USER_NAME
        fields["password"] = USER_PASSWORD
        fields.setdefault("credentialId", "")
        fields["login"] = fields.get("login") or "Sign In"
        origin = f"{urlsplit(str(page.url)).scheme}://{urlsplit(str(page.url)).netloc}"
        shell = client.post(
            action,
            data=fields,
            headers={"Origin": origin, "Referer": str(page.url)},
        )
        assert shell.status_code == 200, shell.text[:800]
        assert "<b>ADS</b>" in shell.text
        assert "Projects" in shell.text
        assert 'id="composer"' in shell.text
