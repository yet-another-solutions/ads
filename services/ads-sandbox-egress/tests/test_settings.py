import base64
import hashlib
import json
import os
import subprocess
import sys
from uuid import uuid4

import pytest

from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.settings import PREFIX, enforcement, load_settings
from test_dnssec_chain import ROOT, PublicDNS
from test_tls import identity as identity


@pytest.fixture
def environment(identity):
    public = PublicDNS()
    generation = str(uuid4())
    raw = {
        name: str(uuid4())
        for name in (
            "SESSION_ID",
            "SANDBOX_ID",
            "PROJECT_ID",
            "STATE_ID",
            "STATE_PVC_UID",
            "WRAPPING_CUSTODY_UID",
            "CA_ATTEMPT",
            "IPC_SERVICE_SUBJECT",
            "POD_UID",
        )
    }
    raw.update(
        ATTACHMENT_GENERATION=generation,
        CREATOR_GENERATION=generation,
        STATE_DEVICE="/dev/ads-egress-state",
        CA_PUBLIC_DEVICE="/dev/ads-ca-public",
        CA_PRIVATE_DEVICE="/dev/ads-ca-private",
        STATE_BYTES=str(64 * 1024**2),
        WRAPPING_KEY_B64=base64.b64encode(bytes(range(32))).decode(),
        WRAPPING_KEY_SHA256=hashlib.sha256(bytes(range(32))).hexdigest(),
        KEYCLOAK_AUDIENCE="ads-sandbox-egress",
        NAMESPACE="ads-sandbox",
        BIND_HOST="10.20.0.3",
        PRIVATE_INTERFACE="eth1",
        UPSTREAM_INTERFACE="eth0",
        PORT="8080",
        PRIVATE_MTU="1340",
        RESOLVER_IPV4="10.96.0.10",
        ENFORCEMENT=json.dumps(
            {
                "format": 1,
                "infrastructure": ["10.0.0.0/8"],
                "translations": [],
                "inventory_version": "test-v1",
                "zones": ["cluster.local", "interlab"],
                "exact_names": ["auth.example"],
                "ech_public_name": "cover.example",
                "anchors": [{"name": ".", "keys": [str(key) for key in public.keys[ROOT]]}],
            }
        ),
        KEYCLOAK_ISSUER="https://auth.example/realms/ads",
        KEYCLOAK_WELL_KNOWN_URL="https://auth.example/realms/ads/.well-known/openid-configuration",
        TLS_CERT_PEM=identity.certificate.decode(),
        TLS_KEY_PEM=identity.private_key.decode(),
    )
    return {PREFIX + name: value for name, value in raw.items()}


def test_complete_settings_are_private_and_bound(environment):
    settings = load_settings(environment, resolv_conf="")
    assert settings.pair.sandbox_id == settings.devices.identity.sandbox_id
    assert settings.devices.attachment_generation == settings.devices.creator_generation
    assert settings.network.mac.startswith("02:")
    assert settings.enforcement.resolver.upstreams[0].compressed == "10.96.0.10"
    for name in ("WRAPPING_KEY_B64", "TLS_CERT_PEM", "TLS_KEY_PEM"):
        assert environment[PREFIX + name] not in repr(settings)


@pytest.mark.parametrize(
    "name,value",
    [
        ("SANDBOX_ID", "wrong"),
        ("POD_UID", ""),
        ("STATE_PVC_UID", "different"),
        ("CREATOR_GENERATION", ""),
        ("STATE_BYTES", "1"),
        ("STATE_BYTES", "064"),
        ("STATE_DEVICE", "/dev/other"),
        ("PRIVATE_INTERFACE", "eth9"),
        ("PORT", "53"),
        ("PRIVATE_MTU", "1"),
        ("BIND_HOST", "0.0.0.0"),
        ("RESOLVER_IPV4", "127.0.0.1"),
        ("WRAPPING_KEY_B64", "wrong"),
        ("WRAPPING_KEY_SHA256", "a" * 64),
        ("KEYCLOAK_AUDIENCE", "ads"),
        ("KEYCLOAK_ISSUER", "http://auth.example"),
        ("KEYCLOAK_WELL_KNOWN_URL", "https://secret:password@auth.example"),
        ("NAMESPACE", "bad space"),
        ("TLS_CERT_PEM", "secret-invalid"),
        ("TLS_KEY_PEM", "secret-invalid"),
        ("TLS_CA_PEM", "secret-invalid"),
        ("ENFORCEMENT", "{}"),
    ],
)
def test_bad_manager_input_fails_before_effects_without_echo(environment, name, value):
    environment[PREFIX + name] = value
    with pytest.raises(ValueError) as failure:
        load_settings(environment, resolv_conf="")
    assert str(failure.value) == "invalid egress manager configuration"
    assert failure.value.__suppress_context__


@pytest.mark.parametrize(
    "field,value",
    [
        ("format", True),
        ("format", 2),
        ("infrastructure", []),
        ("infrastructure", ["10.0.0.1/8"]),
        ("translations", [1]),
        ("zones", []),
        ("zones", ["."]),
        ("anchors", []),
        ("anchors", [{"name": "relative", "keys": []}]),
        ("ech_public_name", "10.0.0.1"),
        ("ech_public_name", "auth.example"),
        ("inventory_version", ""),
    ],
)
def test_enforcement_requires_complete_explicit_trust_inventory(environment, field, value):
    config = json.loads(environment[PREFIX + "ENFORCEMENT"])
    config[field] = value
    with pytest.raises((ValueError, RequestDenied)):
        enforcement(json.dumps(config), namespace="ads", resolver="10.96.0.10", resolv_conf="")


def test_duplicate_enforcement_key_rejected(environment):
    wire = environment[PREFIX + "ENFORCEMENT"]
    with pytest.raises(ValueError, match="duplicate"):
        enforcement(
            wire[:-1] + ', "format": 1}', namespace="ads", resolver="10.96.0.10", resolv_conf=""
        )


def test_entrypoint_invalid_settings_no_effects_or_secret_echo():
    env = {name: value for name, value in os.environ.items() if not name.startswith(PREFIX)}
    env[PREFIX + "TLS_KEY_PEM"] = "secret-sentinel"
    result = subprocess.run(
        [sys.executable, "-m", "ads_sandbox_egress"],
        env=env,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 3 and not result.stdout
    assert result.stderr == b"egress runtime failed closed\n"
