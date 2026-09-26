# ruff: noqa: F811
from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from ads_sandbox_manager.config import CaSettings
from ads_sandbox_manager.egress_compute import EgressRuntime, egress_pod
from ads_sandbox_manager.egress_state_kube import decode_key, identity, key_secret
from ads_sandbox_manager.egress_state_store import EgressState, WrappingKey
from ads_sandbox_manager.pair_objects import compute_identity, control_service, placement
from ads_sandbox_manager.session_objects import ca_consumer_name
from test_pair_objects import pair  # noqa: F401
from test_session_objects import object_settings as base_settings  # noqa: F401


@pytest.fixture
def object_settings(base_settings):
    return replace(base_settings, ca=CaSettings("registry.test/ca:v1", "signer", "extra"))


@pytest.fixture
def runtime():
    return EgressRuntime(
        "registry.test/egress@sha256:" + "a" * 64,
        "kata-egress",
        "egress-tls",
        1450,
        1000,
        512,
        "10.96.0.10",
        "https://auth.test/realms/ads",
        "https://auth.test/realms/ads/.well-known/openid-configuration",
        uuid4(),
        "egress-enforcement",
    )


@pytest.fixture
def state(object_settings, pair):
    return EgressState(
        state_id=uuid4(),
        session_id=pair.session_id,
        sandbox_id=pair.sandbox_id,
        project_id=pair.project_id,
        creator_generation=pair.generation,
        claim_owner=uuid4(),
        claim_changed=datetime.now(UTC),
        namespace=object_settings.namespace,
        storage_bytes=1024**3,
        key_fingerprint=WrappingKey(bytes(range(32))).fingerprint,
        key_dispatch="settled",
        key_uid=str(uuid4()),
        volume_dispatch="settled",
        volume_uid=str(uuid4()),
    )


def test_fixed_isolated_kata_pod_and_control_identity(object_settings, pair, state, runtime):
    attempt = uuid4()
    pod = egress_pod(object_settings, pair, attempt, state, runtime)
    assert {k: v for k, v in pod.items() if k != "spec"} == compute_identity(
        object_settings, pair, "egress"
    )
    spec = pod["spec"]
    assert spec["schedulingGroup"] == placement(pair, "egress")["schedulingGroup"]
    assert spec["runtimeClassName"] == runtime.runtime_class
    assert spec["restartPolicy"] == "Never" and spec["terminationGracePeriodSeconds"] == 30
    assert spec["automountServiceAccountToken"] is False
    assert spec["enableServiceLinks"] is False
    assert spec["nodeSelector"] == object_settings.node_selector
    assert spec["tolerations"] == object_settings.tolerations
    assert spec["imagePullSecrets"] == [{"name": n} for n in object_settings.image_pull_secrets]
    assert spec["dnsPolicy"] == "None"
    assert spec["dnsConfig"] == {"nameservers": [runtime.resolver_ipv4]}
    assert (
        not {
            "hostNetwork",
            "hostPID",
            "hostIPC",
            "nodeName",
            "initContainers",
            "serviceAccountName",
            "readinessGates",
        }
        & spec.keys()
    )
    assert len(spec["containers"]) == 1
    container = spec["containers"][0]
    assert container["name"] == "egress"
    assert container["image"] == runtime.image
    assert container["imagePullPolicy"] == "IfNotPresent"
    assert container["command"] == ["python", "-m", "ads_sandbox_egress"]
    assert (
        not {
            "args",
            "envFrom",
            "readinessProbe",
            "startupProbe",
            "livenessProbe",
        }
        & container.keys()
    )
    assert container["resources"] == {
        "requests": {"cpu": "1000m", "memory": "512Mi"},
        "limits": {"cpu": "1000m", "memory": "512Mi"},
    }
    assert container["securityContext"] == {
        "runAsUser": 0,
        "runAsGroup": 0,
        "privileged": False,
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {
            "drop": ["ALL"],
            "add": ["SYS_ADMIN", "NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE"],
        },
        "seccompProfile": {"type": "Unconfined"},
        "appArmorProfile": {"type": "Unconfined"},
    }
    service = control_service(object_settings, pair, "egress")
    assert all(pod["metadata"]["labels"][k] == v for k, v in service["spec"]["selector"].items())
    assert container["ports"] == [{"name": "https", "containerPort": 8080, "protocol": "TCP"}]
    assert service["spec"]["ports"][0]["targetPort"] == 8080
    env = {v["name"].removeprefix("ADS_SANDBOX_EGRESS_"): v for v in container["env"]}
    assert len(env) == len(container["env"])
    for name, value in {
        "SESSION_ID": pair.session_id,
        "SANDBOX_ID": pair.sandbox_id,
        "PROJECT_ID": pair.project_id,
        "ATTACHMENT_GENERATION": pair.generation,
        "STATE_ID": state.state_id,
        "STATE_BYTES": state.storage_bytes,
        "STATE_PVC_UID": state.volume_uid,
        "WRAPPING_CUSTODY_UID": state.key_uid,
        "WRAPPING_KEY_SHA256": state.key_fingerprint,
        "CA_ATTEMPT": attempt,
        "PRIVATE_INTERFACE": "eth1",
        "PRIVATE_MTU": 1340,
        "UPSTREAM_INTERFACE": "eth0",
        "RESOLVER_IPV4": runtime.resolver_ipv4,
        "KEYCLOAK_ISSUER": runtime.keycloak_issuer,
        "KEYCLOAK_WELL_KNOWN_URL": runtime.keycloak_well_known_url,
        "KEYCLOAK_AUDIENCE": "ads-sandbox-egress",
        "IPC_SERVICE_SUBJECT": runtime.ipc_service_subject,
        "PORT": 8080,
    }.items():
        assert env[name]["value"] == str(value)
    for name, field in (("POD_UID", "metadata.uid"), ("BIND_HOST", "status.podIP")):
        assert env[name]["valueFrom"] == {"fieldRef": {"apiVersion": "v1", "fieldPath": field}}
    for name, secret, key in (
        ("WRAPPING_KEY_B64", identity(state, "key")["metadata"]["name"], "wrapping.b64"),
        ("TLS_CERT_PEM", runtime.tls_secret, "tls.crt"),
        ("TLS_KEY_PEM", runtime.tls_secret, "tls.key"),
    ):
        assert env[name] == {
            "name": "ADS_SANDBOX_EGRESS_" + name,
            "valueFrom": {"secretKeyRef": {"name": secret, "key": key, "optional": False}},
        }
    assert "wrapping.key" not in json.dumps(pod)
    assert base64.b64encode(bytes(range(32))).decode() not in json.dumps(pod)
    assert spec["volumes"] == [
        {"name": "runtime", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}},
        {
            "name": "state",
            "persistentVolumeClaim": {"claimName": identity(state, "volume")["metadata"]["name"]},
        },
        *[
            {
                "name": name,
                "persistentVolumeClaim": {
                    "claimName": ca_consumer_name(pair.sandbox_id, role),
                    "readOnly": True,
                },
            }
            for name, role in (("ca-public", "egress"), ("ca-private", "key"))
        ],
    ]
    assert container["volumeMounts"] == [
        {"name": "runtime", "mountPath": "/run/ads-egress", "readOnly": False}
    ]
    assert env["CREATOR_GENERATION"]["value"] == str(state.creator_generation)
    assert env["NAMESPACE"]["value"] == object_settings.namespace
    assert env["ENFORCEMENT"]["valueFrom"] == {
        "configMapKeyRef": {
            "name": "egress-enforcement",
            "key": "enforcement.json",
            "optional": False,
        }
    }
    assert env["TLS_CA_PEM"]["valueFrom"] == {
        "secretKeyRef": {"name": runtime.tls_secret, "key": "ca.crt", "optional": True}
    }
    assert container["volumeDevices"] == [
        {"name": name, "devicePath": env[variable]["value"]}
        for name, variable in (
            ("state", "STATE_DEVICE"),
            ("ca-public", "CA_PUBLIC_DEVICE"),
            ("ca-private", "CA_PRIVATE_DEVICE"),
        )
    ]
    # Mutating returned Kubernetes data must not mutate trusted settings.
    spec["nodeSelector"]["foreign"] = "true"
    spec["tolerations"][0]["key"] = "foreign"
    assert "foreign" not in object_settings.node_selector
    assert object_settings.tolerations[0]["key"] == "sandbox"


@pytest.mark.parametrize(
    "field",
    [
        "session_id",
        "sandbox_id",
        "project_id",
        "creator_generation",
        "namespace",
    ],
)
def test_state_scope_cannot_cross_pair(object_settings, pair, state, runtime, field):
    setattr(state, field, "other" if field == "namespace" else uuid4())
    with pytest.raises(ValueError, match="does not belong"):
        egress_pod(object_settings, pair, uuid4(), state, runtime)


@pytest.mark.parametrize(
    "field,value",
    [
        ("key_dispatch", "inflight"),
        ("volume_dispatch", "inflight"),
        ("key_uid", None),
        ("volume_uid", None),
    ],
)
def test_no_unsettled_or_unbound_custody(object_settings, pair, state, runtime, field, value):
    setattr(state, field, value)
    with pytest.raises((ValueError, RuntimeError)):
        egress_pod(object_settings, pair, uuid4(), state, runtime)


@pytest.mark.parametrize("fault", ["ca", "session", "attempt", "runtime", "custody"])
def test_missing_or_conflicting_platform_contract(object_settings, pair, state, runtime, fault):
    attempt = uuid4()
    if fault == "ca":
        object_settings = replace(object_settings, ca=None)
    elif fault == "session":
        object_settings = replace(object_settings, session_objects=None)
    elif fault == "attempt":
        attempt = str(attempt)
    elif fault == "runtime":
        runtime = replace(
            runtime, runtime_class=object_settings.session_objects.guest_runtime_class
        )
    else:
        runtime = replace(runtime, tls_secret=identity(state, "key")["metadata"]["name"])
    with pytest.raises(ValueError):
        egress_pod(object_settings, pair, attempt, state, runtime)


@pytest.mark.parametrize(
    "field,value",
    [
        ("image", "registry.test/egress:latest"),
        ("image", None),
        ("runtime_class", ""),
        ("runtime_class", "ordinary/runtime"),
        ("runtime_class", "a" * 64),
        ("tls_secret", "a..b"),
        ("tls_secret", None),
        ("tls_secret", "a" * 64),
        ("tls_secret", ("a." * 127) + "a"),
        ("transport_mtu", 685),
        ("transport_mtu", 65536),
        ("transport_mtu", True),
        ("cpu_millis", 0),
        ("cpu_millis", 64001),
        ("cpu_millis", "1000"),
        ("memory_mib", 127),
        ("memory_mib", 65537),
        ("resolver_ipv4", "localhost"),
        ("resolver_ipv4", "::1"),
        ("resolver_ipv4", "0.0.0.0"),
        ("resolver_ipv4", "127.0.0.1"),
        ("resolver_ipv4", "169.254.1.1"),
        ("resolver_ipv4", "224.0.0.1"),
        ("resolver_ipv4", "255.255.255.255"),
        ("resolver_ipv4", 1),
        ("keycloak_issuer", "http://auth.test"),
        ("keycloak_issuer", "https://user:secret@auth.test"),
        ("keycloak_issuer", "https://auth.test?secret=value"),
        ("keycloak_issuer", "https://auth.test/#fragment"),
        ("keycloak_issuer", "https://auth.test:99999"),
        ("keycloak_issuer", "https://auth.test:bad"),
        ("keycloak_issuer", "https://auth.\ntest"),
        ("keycloak_issuer", None),
        ("keycloak_well_known_url", "https:///path"),
        ("ipc_service_subject", "not-a-uuid"),
    ],
)
def test_runtime_rejects_untrusted_platform_inputs(runtime, field, value):
    with pytest.raises(ValueError):
        replace(runtime, **{field: value})


def test_custody_text_roundtrip_preserves_every_raw_byte(state):
    key = WrappingKey(bytes(range(32)))
    secret = key_secret(state, key)
    assert secret["immutable"] is True and secret["type"] == "Opaque"
    assert secret["metadata"]["labels"]["ads.io/egress-state-format"] == "v2"
    assert identity(state, "volume")["metadata"]["labels"]["ads.io/egress-state-format"] == "v1"
    delivered = base64.b64decode(secret["data"]["wrapping.b64"], validate=True).decode("ascii")
    assert "\x00" not in delivered
    assert base64.b64decode(delivered, validate=True) == key.value
    assert decode_key(secret["data"], key.fingerprint) == key
    assert repr(key) == "WrappingKey()"


@pytest.mark.parametrize(
    "text",
    [
        b"",
        b"not base64",
        b"\xff",
        base64.b64encode(b"x" * 31),
        base64.b64encode(bytes(range(32))) + b"\n",
        base64.b64encode(bytes(range(32)))[:-2] + b"9=",  # Same bytes, nonzero pad bits.
    ],
)
def test_text_custody_is_canonical_and_redacts_failure(state, text):
    with pytest.raises(ValueError, match="^invalid persistent wrapping custody$"):
        decode_key({"wrapping.b64": base64.b64encode(text).decode()}, state.key_fingerprint)


def test_raw_v1_custody_is_not_adopted_or_silently_converted(state):
    with pytest.raises(ValueError, match="^invalid persistent wrapping custody$"):
        decode_key(
            {"wrapping.key": base64.b64encode(bytes(range(32))).decode()}, state.key_fingerprint
        )
    with pytest.raises(ValueError, match="^invalid persistent wrapping custody$"):
        decode_key(
            {"wrapping.b64": base64.b64encode(bytes(range(32))).decode()}, state.key_fingerprint
        )
