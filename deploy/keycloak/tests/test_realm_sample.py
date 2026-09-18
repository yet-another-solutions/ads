"""Contract checks for the exact standalone sample published by CD."""

import json
import re
from pathlib import Path
from uuid import UUID

import yaml

ROOT = Path(__file__).resolve().parents[3]
SAMPLE = ROOT / "deploy/keycloak/ads-realm-import.sample.yaml"
CLIENTS = {
    "ads",
    "ads-engine",
    "ads-preferences",
    "ads-sandbox-mcp",
    "ads-sandbox-manager",
    "ads-sandbox-ipc",
}
AUDIENCES = {
    "ads": {"ads", "ads-engine", "ads-preferences"},
    "ads-engine": {"ads-sandbox-mcp"},
    "ads-preferences": {"ads-preferences"},
    "ads-sandbox-mcp": {"ads-sandbox-manager"},
    "ads-sandbox-manager": {"ads-sandbox-manager", "ads-sandbox-ipc", "ads-sandbox-mcp"},
    "ads-sandbox-ipc": {"ads-sandbox-manager"},
}


def test_operator_resource_and_secret_placeholders():
    text = SAMPLE.read_text()
    document = yaml.safe_load(text)
    assert document["apiVersion"] == "k8s.keycloak.org/v2beta1"
    assert document["kind"] == "KeycloakRealmImport"
    assert document["metadata"]["namespace"] == "keycloak"
    spec = document["spec"]
    assert spec["keycloakCRName"] == "keycloak"
    placeholders = spec["placeholders"]
    assert set(re.findall(r"\$\{([A-Z_]+)\}", text)) == set(placeholders)
    assert len(placeholders) == 6
    assert {p["secret"]["key"] for p in placeholders.values()} == CLIENTS
    for placeholder in placeholders.values():
        assert placeholder["secret"]["name"] == "ads-realm-client-secrets"
    for client in spec["realm"]["clients"]:
        name = client["secret"].removeprefix("${").removesuffix("}")
        assert placeholders[name]["secret"]["key"] == client["clientId"]


def test_flows_scopes_audiences_and_role_assignment():
    realm = yaml.safe_load(SAMPLE.read_text())["spec"]["realm"]
    assert realm["sslRequired"] == "all"
    assert realm["accessTokenLifespan"] > 120
    assert realm["registrationAllowed"] is False
    assert {c["clientId"] for c in realm["clients"]} == CLIENTS
    assert {m["client"] for m in realm["scopeMappings"]} == CLIENTS
    assert all(m["roles"] == ["user"] for m in realm["scopeMappings"])
    assert realm["roles"]["realm"][0]["name"] == "user"
    assert "defaultRoles" not in realm and "defaultRole" not in realm
    for client in realm["clients"]:
        name = client["clientId"]
        assert client["publicClient"] is False
        assert client["fullScopeAllowed"] is False
        assert client["serviceAccountsEnabled"] is True
        assert client["standardFlowEnabled"] == (name == "ads")
        assert client["directAccessGrantsEnabled"] is False
        assert client["implicitFlowEnabled"] is False
        assert client["optionalClientScopes"] == (
            ["ads-engine-ack"] if name == "ads-engine" else []
        )
        assert "offline_access" not in client["defaultClientScopes"]
        assert "basic" in client["defaultClientScopes"]
        if name == "ads-engine":
            assert client["defaultClientScopes"] == ["basic", "service_account"]
            assert (
                client["attributes"]["standard.token.exchange.enableRefreshRequestedTokenType"]
                == "SAME_SESSION"
            )
            assert {m["protocolMapper"] for m in client["protocolMappers"]} == {
                "oidc-audience-mapper",
                "oidc-usermodel-realm-role-mapper",
            }
        else:
            assert "roles" in client["defaultClientScopes"]
        assert client["attributes"]["standard.token.exchange.enabled"] == (
            "false" if name == "ads-preferences" else "true"
        )
        audience_mappers = [
            m for m in client["protocolMappers"] if m["protocolMapper"] == "oidc-audience-mapper"
        ]
        actual_audiences = {m["config"]["included.client.audience"] for m in audience_mappers}
        assert actual_audiences == AUDIENCES[name]
        assert all(m["config"]["access.token.claim"] == "true" for m in audience_mappers)
    browser = next(c for c in realm["clients"] if c["clientId"] == "ads")
    assert browser["redirectUris"] == ["https://ads.example.com/auth/callback"]
    assert browser["webOrigins"] == ["https://ads.example.com"]


def test_engine_ack_scope_is_optional_and_only_adds_ads():
    realm = yaml.safe_load(SAMPLE.read_text())["spec"]["realm"]
    scopes = {s["name"]: s for s in realm["clientScopes"]}
    assert set(scopes) == {
        "basic",
        "roles",
        "profile",
        "email",
        "service_account",
        "ads-engine-ack",
    }
    for client in realm["clients"]:
        assert set(client["defaultClientScopes"] + client["optionalClientScopes"]) <= scopes.keys()
    assert {m["protocolMapper"] for m in scopes["basic"]["protocolMappers"]} == {
        "oidc-sub-mapper",
        "oidc-usersessionmodel-note-mapper",
    }
    assert {m["protocolMapper"] for m in scopes["service_account"]["protocolMappers"]} == {
        "oidc-usersessionmodel-note-mapper"
    }
    scope = next(s for s in realm["clientScopes"] if s["name"] == "ads-engine-ack")
    assert len(scope["protocolMappers"]) == 1
    mapper = scope["protocolMappers"][0]
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    assert mapper["config"]["included.client.audience"] == "ads"
    assert mapper["config"]["access.token.claim"] == "true"
    for client in realm["clients"]:
        assert "ads-engine-ack" not in client["defaultClientScopes"]


def test_lifecycle_subjects_are_service_only_and_admin_protected():
    realm = yaml.safe_load(SAMPLE.read_text())["spec"]["realm"]
    lifecycle = {"ads-sandbox-manager", "ads-sandbox-ipc"}
    users = realm["users"]
    assert {u["serviceAccountClientId"] for u in users} == lifecycle
    for user in users:
        assert "credentials" not in user and "realmRoles" not in user
        client_id = user["serviceAccountClientId"]
        client = next(c for c in realm["clients"] if c["clientId"] == client_id)
        assert UUID(client["id"])
        assert user["attributes"]["ads_service_client_uuid"] == [client["id"]]
    for client in realm["clients"]:
        subjects = [m for m in client["protocolMappers"] if m["config"].get("claim.name") == "sub"]
        assert len(subjects) == (1 if client["clientId"] in lifecycle else 0)
        for mapper in subjects:
            assert mapper["protocolMapper"] == "oidc-usermodel-attribute-mapper"
            assert mapper["config"]["user.attribute"] == "ads_service_client_uuid"
            assert mapper["config"]["access.token.claim"] == "true"
            assert mapper["config"]["id.token.claim"] == "false"
    component = realm["components"]["org.keycloak.userprofile.UserProfileProvider"][0]
    assert component["providerId"] == "declarative-user-profile"
    profile = json.loads(component["config"]["kc.user.profile.config"][0])
    attribute = next(a for a in profile["attributes"] if a["name"] == "ads_service_client_uuid")
    assert attribute["permissions"] == {"view": ["admin"], "edit": ["admin"]}
    assert attribute["multivalued"] is False


def test_cd_publishes_unchanged_sample_separately_from_helm():
    workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    jobs = workflow["jobs"]
    staging = jobs["realm-sample"]
    script = next(s["run"] for s in staging["steps"] if "run" in s)
    assert 'cp deploy/keycloak/ads-realm-import.sample.yaml "dist/' in script
    assert 'cp deploy/keycloak/README.md "dist/' in script
    assert not any(word in script for word in ["envsubst", "kubectl", "curl", "sed "])
    upload = next(s for s in staging["steps"] if "actions/upload-artifact@" in s.get("uses", ""))
    assert "if" not in staging and "if" not in upload
    assert upload["with"]["if-no-files-found"] == "error"
    release = jobs["release"]
    assert "realm-sample" in release["needs"]
    download = next(
        s for s in release["steps"] if "actions/download-artifact@" in s.get("uses", "")
    )
    assert upload["with"]["name"] == download["with"]["name"]
    publish = next(
        s for s in release["steps"] if "softprops/action-gh-release@" in s.get("uses", "")
    )
    assert "dist/*.tgz" in publish["with"]["files"]
    assert "dist/ads-keycloak-realm-*.yaml" in publish["with"]["files"]
    assert "dist/ads-keycloak-realm-*.README.md" in publish["with"]["files"]
    for template in (ROOT / "charts/ads/templates").iterdir():
        assert "kind: KeycloakRealmImport" not in template.read_text()
