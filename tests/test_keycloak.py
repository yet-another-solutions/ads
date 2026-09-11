from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import httpx2
import pytest
import uvicorn

from ads.app import create_app
from ads.config import Settings

docker_ok = shutil.which("docker") is not None
openssl_ok = shutil.which("openssl") is not None
pytestmark = pytest.mark.skipif(
    not docker_ok or not openssl_ok,
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


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _openssl(*args: str) -> None:
    result = subprocess.run(["openssl", *args], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout or "openssl failed")


def _issue_tls(cert_dir: Path) -> Path:
    ca_key = cert_dir / "ca.key"
    ca_crt = cert_dir / "ca.crt"
    server_key = cert_dir / "tls.key"
    server_csr = cert_dir / "tls.csr"
    server_crt = cert_dir / "tls.crt"
    ext = cert_dir / "ext.cnf"
    ext.write_text("[v3_req]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    _openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        "1",
        "-nodes",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_crt),
        "-subj",
        "/CN=ads-test-ca",
    )
    _openssl(
        "req",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-keyout",
        str(server_key),
        "-out",
        str(server_csr),
        "-subj",
        "/CN=127.0.0.1",
    )
    _openssl(
        "x509",
        "-req",
        "-in",
        str(server_csr),
        "-CA",
        str(ca_crt),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(server_crt),
        "-days",
        "1",
        "-sha256",
        "-extfile",
        str(ext),
        "-extensions",
        "v3_req",
    )
    for path in (ca_crt, server_crt, server_key):
        path.chmod(0o644)
    return ca_crt


def _http_client() -> httpx2.Client:
    return httpx2.Client(
        follow_redirects=True,
        timeout=30.0,
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
def keycloak_base(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    pytest.importorskip("testcontainers")
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.wait_strategies import LogMessageWaitStrategy

    cert_dir = tmp_path_factory.mktemp("kc-certs")
    ca_crt = _issue_tls(cert_dir)
    previous = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = str(ca_crt)
    container = (
        DockerContainer(KEYCLOAK_IMAGE)
        .with_exposed_ports(8443)
        .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
        .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .with_env("KC_HOSTNAME_STRICT", "false")
        .with_env("KC_HTTPS_CERTIFICATE_FILE", "/opt/keycloak/certs/tls.crt")
        .with_env("KC_HTTPS_CERTIFICATE_KEY_FILE", "/opt/keycloak/certs/tls.key")
        .with_volume_mapping(str(cert_dir), "/opt/keycloak/certs", "ro")
        .with_command("start-dev")
        .waiting_for(LogMessageWaitStrategy("Listening on").with_startup_timeout(180))
    )
    try:
        with container:
            host = container.get_container_host_ip()
            if host in {"localhost", "0.0.0.0"}:
                host = "127.0.0.1"
            port = container.get_exposed_port(8443)
            yield f"https://{host}:{port}"
    except Exception as exc:
        stdout, stderr = container.get_logs()
        raise RuntimeError(
            f"keycloak failed: {exc}\nstdout={stdout.decode()[-2000:]}\n"
            f"stderr={stderr.decode()[-2000:]}"
        ) from exc
    finally:
        if previous is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = previous


def _admin_token(base: str) -> str:
    response = httpx2.post(
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
    create = httpx2.post(
        f"{base}/admin/realms",
        headers=headers,
        json={"realm": REALM, "enabled": True, "sslRequired": "none"},
        timeout=30.0,
    )
    if create.status_code not in {201, 409}:
        create.raise_for_status()
    httpx2.post(
        f"{base}/admin/realms/{REALM}/roles",
        headers=headers,
        json={"name": "user"},
        timeout=30.0,
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
    )
    if user_resp.status_code not in {201, 409}:
        user_resp.raise_for_status()
    users = httpx2.get(
        f"{base}/admin/realms/{REALM}/users",
        headers=headers,
        params={"username": USER_NAME},
        timeout=30.0,
    )
    users.raise_for_status()
    user_id = users.json()[0]["id"]
    role = httpx2.get(
        f"{base}/admin/realms/{REALM}/roles/user",
        headers=headers,
        timeout=30.0,
    )
    role.raise_for_status()
    mapping = httpx2.post(
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
            httpx2.get(f"{public_base}/health/live", timeout=0.2).raise_for_status()
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
def test_keycloak_login_hello_world_and_button(running_app: str) -> None:
    with _http_client() as client:
        page = client.get(running_app + "/")
        assert page.status_code == 200
        action, fields = _html_form(page.text, "kc-form-login")
        fields["username"] = USER_NAME
        fields["password"] = USER_PASSWORD
        fields.setdefault("credentialId", "")
        fields["login"] = fields.get("login") or "Sign In"
        origin = f"{urlsplit(str(page.url)).scheme}://{urlsplit(str(page.url)).netloc}"
        hello = client.post(
            action,
            data=fields,
            headers={"Origin": origin, "Referer": str(page.url)},
        )
        assert hello.status_code == 200, hello.text[:800]
        assert "hello world" in hello.text
        pressed = client.post(running_app + "/hello/press", follow_redirects=True)
        assert pressed.status_code == 200
        assert "button was pressed" in pressed.text
