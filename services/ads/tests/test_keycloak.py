from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx2
import jwt
import pytest
import uvicorn
import yaml

from ads.app import create_app, create_schema
from ads.config import Settings
from ads.db import create_db_engine
from ads_commons.security import AccessDenied, InvalidAccessToken, ensure_caller
from ads_commons_beans.jwt import JwtVerifier, JwtVerifierSettings
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
    keycloak_tls: KeycloakTls,
) -> Iterator[str]:
    app_port = _free_port()
    public_base = f"https://127.0.0.1:{app_port}"
    verify = _ca_context(keycloak_tls.ca_crt)
    _provision_realm(keycloak_tls.base, f"{public_base}/auth/callback", verify)
    settings = Settings(
        keycloak_well_known_url=f"{keycloak_tls.base}/realms/{REALM}/.well-known/openid-configuration",
        keycloak_issuer=f"{keycloak_tls.base}/realms/{REALM}",
        keycloak_client_id=CLIENT_ID,
        keycloak_client_secret=CLIENT_SECRET,
        keycloak_audience=CLIENT_ID,
        keycloak_role="user",
        session_secret="integration-session-secret!",
        public_base_url=public_base,
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


@pytest.mark.integration
def test_published_realm_sample_import_and_identity(keycloak_tls: KeycloakTls) -> None:
    """Import the actual sample, not a second hand-built approximation of its clients."""
    root = Path(__file__).resolve().parents[3]
    sample_path = root / "deploy/keycloak/ads-realm-import.sample.yaml"
    document = yaml.safe_load(sample_path.read_text())
    # Values exist only in this disposable CI realm; no lab credentials are read.
    rendered = json.dumps(document["spec"]["realm"])
    secrets = {}
    for placeholder, reference in document["spec"]["placeholders"].items():
        client_id = reference["secret"]["key"]
        secrets[client_id] = f"ci-only-{client_id}-secret"
        rendered = rendered.replace("${" + placeholder + "}", secrets[client_id])
    realm = json.loads(rendered)
    realm_name = "ads-published-sample"
    realm["realm"] = realm_name
    verify = _ca_context(keycloak_tls.ca_crt)
    issuer = f"{keycloak_tls.base}/realms/{realm_name}"
    admin_path = f"/admin/realms/{realm_name}"
    headers = {"Authorization": "Bearer " + _admin_token(keycloak_tls.base, verify)}

    with httpx2.Client(base_url=keycloak_tls.base, verify=verify, timeout=30) as http:

        def admin(method: str, path: str, body=None):
            response = http.request(method, path, json=body, headers=headers)
            response.raise_for_status()
            return response.json() if response.content else None

        def token(body: dict, *, allowed: bool = True):
            response = http.post(f"/realms/{realm_name}/protocol/openid-connect/token", data=body)
            if not allowed:
                assert response.status_code in {400, 403}
                return None
            response.raise_for_status()
            return response.json()

        def verifier(audience: str) -> JwtVerifier:
            jwks = issuer + "/protocol/openid-connect/certs"
            return JwtVerifier(
                JwtVerifierSettings(issuer, audience, audience, jwks, verify),
                jwt.PyJWKClient(jwks, ssl_context=verify),
            )

        def exchange(
            caller: str,
            audience: str,
            subject: str,
            *,
            allowed: bool = True,
            has_user_role: bool = True,
        ):
            result = token(
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "client_id": caller,
                    "client_secret": secrets[caller],
                    "subject_token": subject,
                    "audience": audience,
                    **(
                        {"scope": "ads-engine-ack"}
                        if caller == "ads-engine" and audience == "ads"
                        else {"scope": "ads-engine-context-meter"}
                        if caller == "ads-engine" and audience == "ads-context-meter"
                        else {}
                    ),
                },
                allowed=allowed,
            )
            if not allowed:
                return None
            assert "refresh_token" not in result
            access = result["access_token"]
            checked = verifier(audience)
            context = checked.authenticate(access)
            claims = checked.verified_claims(access)
            assert context.user_id == UUID(user_id)
            ensure_caller(context, caller)
            assert claims["aud"] == audience or claims["aud"] == [audience]
            assert ("user" in claims.get("realm_access", {}).get("roles", [])) is has_user_role
            assert claims["exp"] - claims["iat"] > 120
            with pytest.raises(AccessDenied):
                ensure_caller(context, "not-an-authorized-caller")
            return access

        admin("POST", "/admin/realms", realm)
        try:
            # No post-import client or profile repair: the published document must suffice.
            profile = admin("GET", admin_path + "/users/profile")
            protected = next(
                a for a in profile["attributes"] if a["name"] == "ads_service_client_uuid"
            )
            assert protected["permissions"] == {"view": ["admin"], "edit": ["admin"]}
            clients = {
                c["clientId"]: c
                for c in admin("GET", admin_path + "/clients")
                if c["clientId"] in secrets
            }
            assert len(clients) == 7
            for name, client in clients.items():
                assert client["directAccessGrantsEnabled"] is False
                assert client["standardFlowEnabled"] == (name == "ads")
                assert client["fullScopeAllowed"] is False
                imported_scopes = admin(
                    "GET", admin_path + f"/clients/{client['id']}/default-client-scopes"
                )
                expected = next(c for c in realm["clients"] if c["clientId"] == name)
                assert {s["name"] for s in imported_scopes} == set(expected["defaultClientScopes"])

            # Humans are deliberately absent from the sample; provision a CI-only user.
            admin(
                "POST",
                admin_path + "/users",
                {
                    "username": "sample-user",
                    "enabled": True,
                    "email": "sample@example.com",
                    "emailVerified": True,
                    "firstName": "Sample",
                    "lastName": "User",
                    "credentials": [
                        {"type": "password", "value": "sample-ci-password", "temporary": False}
                    ],
                },
            )
            user_id = admin("GET", admin_path + "/users?username=sample-user&exact=true")[0]["id"]
            role = admin("GET", admin_path + "/roles/user")
            admin("POST", admin_path + f"/users/{user_id}/role-mappings/realm", [role])

            # Real browser authorization-code flow, without enabling password grants.
            redirect_uri = clients["ads"]["redirectUris"][0]
            page = http.get(
                f"/realms/{realm_name}/protocol/openid-connect/auth",
                params={
                    "client_id": "ads",
                    "redirect_uri": redirect_uri,
                    "response_type": "code",
                    "scope": "openid profile email",
                    "state": "sample-state",
                    "nonce": "sample-nonce",
                },
            )
            page.raise_for_status()
            action, fields = _html_form(page.text, "kc-form-login")
            fields.update({"username": "sample-user", "password": "sample-ci-password"})
            login = http.post(action, data=fields)
            assert login.status_code == 302
            location = urlsplit(login.headers["location"])
            assert location.netloc == "ads.example.com"
            query = parse_qs(location.query)
            assert query["state"] == ["sample-state"]
            browser = token(
                {
                    "grant_type": "authorization_code",
                    "client_id": "ads",
                    "client_secret": secrets["ads"],
                    "redirect_uri": redirect_uri,
                    "code": query["code"][0],
                }
            )
            initial = browser["access_token"]
            assert verifier("ads").authenticate(initial).user_id == UUID(user_id)
            assert browser["refresh_token"]
            refreshed = token(
                {
                    "grant_type": "refresh_token",
                    "client_id": "ads",
                    "client_secret": secrets["ads"],
                    "refresh_token": browser["refresh_token"],
                }
            )
            assert verifier("ads").authenticate(refreshed["access_token"]).user_id == UUID(user_id)

            exchange("ads", "ads-preferences", initial)
            engine = exchange("ads", "ads-engine", initial)
            acknowledge = exchange("ads-engine", "ads", engine)
            exchange("ads", "ads-engine", acknowledge)
            current = engine
            for caller, audience in [
                ("ads-engine", "ads-sandbox-mcp"),
                ("ads-sandbox-mcp", "ads-sandbox-manager"),
                ("ads-sandbox-manager", "ads-sandbox-ipc"),
                ("ads-sandbox-ipc", "ads-sandbox-manager"),
                ("ads-sandbox-manager", "ads-sandbox-mcp"),
            ]:
                with pytest.raises(InvalidAccessToken):
                    verifier(audience).authenticate(current)
                current = exchange(caller, audience, current)
            exchange("ads-sandbox-ipc", "ads-sandbox-mcp", initial, allowed=False)
            exchange("ads-preferences", "ads", initial, allowed=False)
            exchange("ads", "ads-context-meter", initial, allowed=False)
            pair = token(
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "client_id": "ads-engine",
                    "client_secret": secrets["ads-engine"],
                    "subject_token": engine,
                    "audience": "ads-sandbox-mcp",
                }
            )
            for _ in range(3):
                assert pair["refresh_token"] and pair["refresh_expires_in"] > 0
                checked = verifier("ads-sandbox-mcp")
                claims = checked.verified_claims(pair["access_token"])
                assert claims["sub"] == user_id and claims["azp"] == "ads-engine"
                assert claims["aud"] in ("ads-sandbox-mcp", ["ads-sandbox-mcp"])
                assert set(claims["realm_access"]["roles"]) == {"user"}
                assert not claims.get("resource_access")
                assert "ads-engine-ack" not in claims.get("scope", "").split()
                assert "ads-engine-context-meter" not in claims.get("scope", "").split()
                assert claims["exp"] - claims["iat"] > 240
                pair = token(
                    {
                        "grant_type": "refresh_token",
                        "client_id": "ads-engine",
                        "client_secret": secrets["ads-engine"],
                        "refresh_token": pair["refresh_token"],
                    }
                )
            # Revocation is recomputed on refresh, never copied from the first pair.
            admin("DELETE", admin_path + f"/users/{user_id}/role-mappings/realm", [role])
            revoked = token(
                {
                    "grant_type": "refresh_token",
                    "client_id": "ads-engine",
                    "client_secret": secrets["ads-engine"],
                    "refresh_token": pair["refresh_token"],
                }
            )
            claims = verifier("ads-sandbox-mcp").verified_claims(revoked["access_token"])
            assert "user" not in claims.get("realm_access", {}).get("roles", [])
            roleless_engine = exchange("ads", "ads-engine", initial, has_user_role=False)
            meter = exchange(
                "ads-engine",
                "ads-context-meter",
                roleless_engine,
                has_user_role=False,
            )
            meter_claims = verifier("ads-context-meter").verified_claims(meter)
            assert "ads-engine-context-meter" in meter_claims.get("scope", "").split()
            assert not meter_claims.get("resource_access")
            token(
                {
                    "grant_type": "password",
                    "client_id": "ads",
                    "client_secret": secrets["ads"],
                    "username": "sample-user",
                    "password": "sample-ci-password",
                },
                allowed=False,
            )
            for caller in ["ads-sandbox-manager", "ads-sandbox-ipc"]:
                lifecycle = token(
                    {
                        "grant_type": "client_credentials",
                        "client_id": caller,
                        "client_secret": secrets[caller],
                    }
                )["access_token"]
                checked = verifier("ads-sandbox-manager")
                context = checked.authenticate(lifecycle)
                service_user = admin(
                    "GET", admin_path + f"/clients/{clients[caller]['id']}/service-account-user"
                )
                assert context.user_id == UUID(service_user["id"])
                assert context.user_id != UUID(clients[caller]["id"])
                ensure_caller(context, caller)
                claims = checked.verified_claims(lifecycle)
                assert "user" not in claims.get("realm_access", {}).get("roles", [])
                hops = (
                    [
                        ("ads-sandbox-manager", "ads-sandbox-ipc"),
                        ("ads-sandbox-ipc", "ads-sandbox-manager"),
                    ]
                    if caller == "ads-sandbox-manager"
                    else [("ads-sandbox-ipc", "ads-sandbox-manager")]
                )
                for sender, audience in hops:
                    pair = token(
                        {
                            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                            "client_id": sender,
                            "client_secret": secrets[sender],
                            "subject_token": lifecycle,
                            "audience": audience,
                        }
                    )
                    assert "refresh_token" not in pair
                    assert pair["access_token"] != lifecycle
                    lifecycle = pair["access_token"]
                    checked = verifier(audience)
                    context = checked.authenticate(lifecycle)
                    assert context.user_id == UUID(service_user["id"])
                    ensure_caller(context, sender)
                    claims = checked.verified_claims(lifecycle)
                    assert claims["aud"] in (audience, [audience])
                    assert "user" not in claims.get("realm_access", {}).get("roles", [])
        finally:
            admin("DELETE", admin_path)
