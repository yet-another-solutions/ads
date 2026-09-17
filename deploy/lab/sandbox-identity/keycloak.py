"""Reconcile slice 6 clients and prove STE using the installed ADS JwtVerifier.

Run in the existing ADS container, not as an ADS application endpoint.
Input is a JSON object of credential filenames (without .md) to secret values.
Only assertion summaries are printed. Tokens remain in memory.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID

import jwt

from ads_commons.security import InvalidAccessToken, ensure_caller
from ads_commons_beans.jwt import JwtVerifier, JwtVerifierSettings

BASE = os.environ["ADS_SLICE6_KEYCLOAK_URL"].rstrip("/")
ISSUER = BASE + "/realms/ads"
TLS = ssl.create_default_context(cafile=os.environ.get("ADS_TLS_CA_BUNDLE"))
SECRETS = json.load(sys.stdin)
ADMIN_TOKEN = ""


def api(method, path, body=None, *, form=False, admin=True, expected=(200, 201, 204)):
    data = None
    headers = {}
    if body is not None:
        data = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
        headers["Content-Type"] = (
            "application/x-www-form-urlencoded" if form else "application/json"
        )
    if admin:
        headers["Authorization"] = "Bearer " + ADMIN_TOKEN
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=TLS, timeout=30) as response:
            status = response.status
            raw = response.read()
    except urllib.error.HTTPError as error:
        # Never print the request, response body, JWT, or secret.
        raise RuntimeError(f"{method} {path}: HTTP {error.code}") from None
    if status not in expected:
        raise RuntimeError(f"{method} {path}: unexpected HTTP {status}")
    return json.loads(raw) if raw else None


def client(name):
    rows = api("GET", "/admin/realms/ads/clients?clientId=" + name)
    assert len(rows) == 1, f"Expected exactly one {name} client"
    return rows[0]


def mapper(c, name, provider, config):
    path = f"/admin/realms/ads/clients/{c['id']}/protocol-mappers/models"
    matches = [m for m in api("GET", path) if m["name"] == name]
    assert len(matches) <= 1
    body = {"name": name, "protocol": "openid-connect", "protocolMapper": provider,
            "consentRequired": False, "config": config}
    if matches:
        body["id"] = matches[0]["id"]
        api("PUT", path + "/" + body["id"], body)
    else:
        api("POST", path, body)


def exchange(caller, audience, subject):
    result = api("POST", "/realms/ads/protocol/openid-connect/token", {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "client_id": caller, "client_secret": SECRETS[caller + "-oidc-client"],
        "subject_token": subject, "audience": audience,
    }, form=True, admin=False)
    assert "refresh_token" not in result
    assert result["access_token"] != subject
    return result["access_token"]


def verify(token, audience, caller, subject, *, user=True):
    verifier = JwtVerifier(
        JwtVerifierSettings(ISSUER, audience, audience, ISSUER + "/protocol/openid-connect/certs", TLS),
        jwt.PyJWKClient(ISSUER + "/protocol/openid-connect/certs", ssl_context=TLS),
    )
    ctx = verifier.authenticate(token)
    claims = verifier.verified_claims(token)
    assert str(ctx.user_id) == subject
    ensure_caller(ctx, caller)
    assert claims["aud"] == audience or claims["aud"] == [audience], "Not downscoped"
    if user:
        assert "user" in claims.get("realm_access", {}).get("roles", [])
    assert claims["exp"] - claims["iat"] > 120
    return verifier, ctx


def main():
    global ADMIN_TOKEN
    ADMIN_TOKEN = api("POST", "/realms/master/protocol/openid-connect/token", {
        "grant_type": "password", "client_id": "admin-cli", "username": "admin",
        "password": SECRETS["keycloak-admin"],
    }, form=True, admin=False)["access_token"]
    # A normal user must never be able to self-assign the service-only subject.
    profile = api("GET", "/admin/realms/ads/users/profile")
    attributes = profile.setdefault("attributes", [])
    subject_attribute = next(
        (a for a in attributes if a["name"] == "ads_service_client_uuid"), None
    )
    if subject_attribute is None:
        subject_attribute = {"name": "ads_service_client_uuid", "multivalued": False}
        attributes.append(subject_attribute)
    subject_attribute["permissions"] = {"view": ["admin"], "edit": ["admin"]}
    api("PUT", "/admin/realms/ads/users/profile", profile)
    names = ("ads-sandbox-mcp", "ads-sandbox-manager", "ads-sandbox-ipc")
    role = api("GET", "/admin/realms/ads/roles/user")
    for name in names:
        found = api("GET", "/admin/realms/ads/clients?clientId=" + name)
        body = found[0] if found else {"clientId": name, "protocol": "openid-connect"}
        body.update({
            "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            "implicitFlowEnabled": False, "fullScopeAllowed": False,
            "secret": SECRETS[name + "-oidc-client"],
            "defaultClientScopes": ["basic", "roles", "service_account"],
            "optionalClientScopes": [],
        })
        body.setdefault("attributes", {}).update({
            "standard.token.exchange.enabled": "true",
            "access.token.lifespan": "300",
        })
        if found:
            api("PUT", "/admin/realms/ads/clients/" + body["id"], body)
        else:
            api("POST", "/admin/realms/ads/clients", body)
        c = client(name)
        api("POST", f"/admin/realms/ads/clients/{c['id']}/scope-mappings/realm", [role])
        if name in ("ads-sandbox-manager", "ads-sandbox-ipc"):
            service_user = api("GET", f"/admin/realms/ads/clients/{c['id']}/service-account-user")
            service_user.setdefault("attributes", {})["ads_service_client_uuid"] = [c["id"]]
            api("PUT", "/admin/realms/ads/users/" + service_user["id"], service_user)
            mapper(c, "ads-service-subject", "oidc-usermodel-attribute-mapper", {
                "user.attribute": "ads_service_client_uuid", "claim.name": "sub",
                "jsonType.label": "String", "multivalued": "false",
                "access.token.claim": "true", "id.token.claim": "false",
                "userinfo.token.claim": "false", "introspection.token.claim": "true",
            })
    for caller, targets in {
        "ads-engine": ["ads-sandbox-mcp"],
        "ads-sandbox-mcp": ["ads-sandbox-manager"],
        "ads-sandbox-manager": ["ads-sandbox-ipc", "ads-sandbox-mcp", "ads-sandbox-manager"],
        "ads-sandbox-ipc": ["ads-sandbox-manager"],
    }.items():
        c = client(caller)
        for target in targets:
            mapper(c, "audience-" + target, "oidc-audience-mapper", {
                "included.client.audience": target, "access.token.claim": "true",
                "id.token.claim": "false", "userinfo.token.claim": "false",
                "introspection.token.claim": "true",
            })
    print("PASS: sandbox clients reconciled; engine existing settings preserved", flush=True)

    # Lifecycle tokens have service identity, never a user holder or user-role check.
    for name, audience in (
        ("ads-sandbox-ipc", "ads-sandbox-manager"),
        ("ads-sandbox-manager", "ads-sandbox-manager"),
    ):
        token = api("POST", "/realms/ads/protocol/openid-connect/token", {
            "grant_type": "client_credentials", "client_id": name,
            "client_secret": SECRETS[name + "-oidc-client"],
        }, form=True, admin=False)["access_token"]
        # Manager has multiple legitimate lifecycle/transit audiences. Verify its
        # required audience normally; strict singleton downscoping applies to STE.
        c = client(name)
        verifier = JwtVerifier(
            JwtVerifierSettings(ISSUER, audience, audience, ISSUER + "/protocol/openid-connect/certs", TLS),
            jwt.PyJWKClient(ISSUER + "/protocol/openid-connect/certs", ssl_context=TLS),
        )
        ctx = verifier.authenticate(token)
        assert ctx.user_id == UUID(c["id"]), "Lifecycle sub must be the client UUID"
        ensure_caller(ctx, name)
        print(f"PASS: {name} client-credentials sub=client UUID verified by ADS", flush=True)

    ads = client("ads")
    original_grants = ads.get("directAccessGrantsEnabled", False)
    try:
        ads["directAccessGrantsEnabled"] = True
        api("PUT", "/admin/realms/ads/clients/" + ads["id"], ads)
        initial = api("POST", "/realms/ads/protocol/openid-connect/token", {
            "grant_type": "password", "client_id": "ads",
            "client_secret": SECRETS["ads-oidc-client"],
            "username": "test", "password": SECRETS["ads-test-user"], "scope": "openid",
        }, form=True, admin=False)["access_token"]
        subject = api("GET", "/admin/realms/ads/users?username=test&exact=true")[0]["id"]
        token = initial
        for caller, audience in (
            ("ads", "ads-engine"),
            ("ads-engine", "ads-sandbox-mcp"),
            ("ads-sandbox-mcp", "ads-sandbox-manager"),
            ("ads-sandbox-manager", "ads-sandbox-ipc"),
            ("ads-sandbox-ipc", "ads-sandbox-manager"),
            ("ads-sandbox-manager", "ads-sandbox-mcp"),
        ):
            incoming = token
            token = exchange(caller, audience, incoming)
            verifier, ctx = verify(token, audience, caller, subject)
            if caller != "ads":
                try:
                    verifier.authenticate(incoming)
                except InvalidAccessToken:
                    pass
                else:
                    raise AssertionError("Forwarded inbound token was accepted")
            try:
                ensure_caller(ctx, "not-an-allowed-caller")
            except Exception as error:
                assert type(error).__name__ == "AccessDenied"
            else:
                raise AssertionError("Disallowed caller was accepted")
            print(f"PASS: STE {caller} -> {audience}; UUID sub/role/aud/azp/TTL; negative checks", flush=True)
        # Direct service-to-service bypasses must fail at Keycloak's audience checks.
        try:
            exchange("ads-sandbox-ipc", "ads-sandbox-mcp", token)
        except RuntimeError:
            print("PASS: unrelated client cannot exchange a token not addressed to it", flush=True)
        else:
            raise AssertionError("Unrelated exchange succeeded")
    finally:
        current = client("ads")
        current["directAccessGrantsEnabled"] = original_grants
        api("PUT", "/admin/realms/ads/clients/" + current["id"], current)
        assert client("ads")["directAccessGrantsEnabled"] == original_grants
        print("PASS: temporary direct grant restored", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAILED: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)
