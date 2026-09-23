# ruff: noqa: F811
from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from ads_sandbox_manager.pair_compute import (
    RelayRuntime,
    relay_configuration,
    relay_input_name,
    relay_pod,
)
from ads_sandbox_manager.pair_objects import compute_identity, control_service, placement
from test_pair_objects import pair  # noqa: F401
from test_session_objects import object_settings  # noqa: F401

PEER_KEY = base64.b64encode(bytes(range(32))).decode()


@pytest.fixture
def runtime():
    return RelayRuntime("registry.test/ads-ptp-tools@sha256:" + "a" * 64, "relay-health-tls", 1450)


@pytest.fixture
def relay_parser():
    path = Path(__file__).parents[3] / "services/ads-ptp-tools/ads-ptp-relay"
    loader = importlib.machinery.SourceFileLoader("manager_relay_contract", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize("role", ["guest-relay", "egress-relay"])
def test_relay_pod_is_fixed_ordinary_runtime_with_separate_protected_inputs(
    object_settings, pair, runtime, role
):
    pod = relay_pod(object_settings, pair, role, runtime)
    assert {k: v for k, v in pod.items() if k != "spec"} == compute_identity(
        object_settings, pair, role
    )
    spec = pod["spec"]
    assert spec["schedulingGroup"] == placement(pair, role)["schedulingGroup"]
    assert spec["restartPolicy"] == "Always"
    assert spec["terminationGracePeriodSeconds"] == 30
    assert not spec["automountServiceAccountToken"] and not spec["enableServiceLinks"]
    assert spec["nodeSelector"] == object_settings.node_selector
    assert spec["tolerations"] == object_settings.tolerations
    assert spec["imagePullSecrets"] == [{"name": n} for n in object_settings.image_pull_secrets]
    assert (
        not {
            "hostNetwork",
            "hostPID",
            "hostIPC",
            "runtimeClassName",
            "nodeName",
            "initContainers",
            "serviceAccountName",
            "readinessGates",
        }
        & spec.keys()
    )
    assert len(spec["containers"]) == 1
    container = spec["containers"][0]
    assert container["name"] == "relay"
    assert container["image"] == runtime.image
    assert container["securityContext"] == {
        "runAsUser": 0,
        "runAsGroup": 0,
        "privileged": False,
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN", "NET_ADMIN", "NET_RAW"]},
        "seccompProfile": {"type": "Unconfined"},
        "appArmorProfile": {"type": "Unconfined"},
    }
    assert container["env"] == [
        {
            "name": "POD_UID",
            "valueFrom": {
                "fieldRef": {
                    "apiVersion": "v1",
                    "fieldPath": "metadata.uid",
                }
            },
        },
        {"name": "ATTACHMENT_GENERATION", "value": str(pair.generation)},
    ]
    assert container["resources"] == {
        "requests": {"cpu": "1000m", "memory": "256Mi"},
        "limits": {"cpu": "1000m", "memory": "256Mi"},
    }
    mounts = container["volumeMounts"]
    files = mounts[2:]
    assert files == [
        {"name": source, "mountPath": "/inputs/" + key, "subPath": key, "readOnly": True}
        for source, keys in (("config", ("config.json", "wg.key")), ("tls", ("tls.crt", "tls.key")))
        for key in keys
    ]
    assert spec["volumes"][:2] == [
        {"name": "run", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}},
        {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
    ]
    for volume, name, keys in (
        (spec["volumes"][2], relay_input_name(pair, role), ["config.json", "wg.key"]),
        (spec["volumes"][3], runtime.tls_secret, ["tls.crt", "tls.key"]),
    ):
        assert volume["secret"] == {
            "secretName": name,
            "defaultMode": 0o400,
            "optional": False,
            "items": [{"key": key, "path": key} for key in keys],
        }
    assert not any("hostPath" in v or "persistentVolumeClaim" in v for v in spec["volumes"])
    assert not {"args", "envFrom", "readinessProbe", "startupProbe"} & container.keys()
    assert container["command"] == [
        "python",
        "/usr/local/bin/ads-ptp-relay",
        "--config",
        "/inputs/config.json",
        "--key",
        "/inputs/wg.key",
        "--cert",
        "/inputs/tls.crt",
        "--tls-key",
        "/inputs/tls.key",
        "--state",
        "/run/relay-state",
        "--port",
        "8443",
    ]


@pytest.mark.parametrize("role", ["guest-relay", "egress-relay"])
def test_no_peer_dependent_endpoint_gate_and_direct_health_matches_ipc(
    object_settings, pair, runtime, role
):
    pod = relay_pod(object_settings, pair, role, runtime)
    container = pod["spec"]["containers"][0]
    assert "readinessProbe" not in container and "startupProbe" not in container
    assert "readinessGates" not in pod["spec"]
    assert container["livenessProbe"] == {
        "httpGet": {"path": "/health", "port": "https", "scheme": "HTTPS"},
        "initialDelaySeconds": 90,
        "periodSeconds": 10,
        "timeoutSeconds": 7,
        "failureThreshold": 3,
    }
    service = control_service(object_settings, pair, role)
    assert all(pod["metadata"]["labels"][k] == v for k, v in service["spec"]["selector"].items())
    ports = {p["name"]: p["containerPort"] for p in container["ports"]}
    assert ports["https"] == service["spec"]["ports"][0]["targetPort"] == 8443
    assert ports["wireguard"] == 51820


@pytest.mark.parametrize("role", ["guest-relay", "egress-relay"])
@pytest.mark.parametrize("mtu", [686, 1450, 65535])
def test_generated_configuration_passes_actual_relay_parser(pair, runtime, relay_parser, role, mtu):
    uid = uuid4()
    config = relay_configuration(
        pair,
        role,
        uid,
        PEER_KEY,
        replace(runtime, transport_mtu=mtu),
        "10.32.0.99" if role == "guest-relay" else None,
    )
    encoded = json.dumps(config)
    parsed = json.loads(encoded, object_pairs_hook=relay_parser.pairs)
    assert relay_parser.validate(parsed, str(uid), str(pair.generation)) == config
    assert config["transport_mtu"] == mtu
    assert config["sandbox_id"] == str(pair.sandbox_id)
    assert config["side"] == role.removesuffix("-relay")
    assert "private_key" not in config and "wg.key" not in config
    assert config["endpoint"] == ("10.32.0.99:51820" if role == "guest-relay" else None)
    with pytest.raises(ValueError, match="identity changed"):
        relay_parser.validate(parsed, str(uuid4()), str(pair.generation))
    with pytest.raises(ValueError, match="identity changed"):
        relay_parser.validate(parsed, str(uid), str(uuid4()))


def test_two_relay_payloads_are_exact_inverse_peers(pair, runtime):
    guest = relay_configuration(pair, "guest-relay", uuid4(), PEER_KEY, runtime, "10.32.0.99")
    egress = relay_configuration(pair, "egress-relay", uuid4(), PEER_KEY, runtime)
    assert guest["local_private"] == egress["peer_private"] == "10.10.30.2/24"
    assert guest["peer_private"] == egress["local_private"] == "10.10.30.1/24"
    assert guest["local_tunnel"] == egress["peer_tunnel"] == "10.10.40.2/32"
    assert guest["peer_tunnel"] == egress["local_tunnel"] == "10.10.40.1/32"
    assert guest["wireguard_port"] == egress["wireguard_port"] == 51820
    assert guest["vxlan_port"] == egress["vxlan_port"] == 4789
    assert guest["vni"] == egress["vni"] == 42
    assert guest["packet_rate"] == egress["packet_rate"] == 10000


def test_input_names_change_per_role_sandbox_and_generation(pair):
    names = {
        relay_input_name(p, role)
        for p in (pair, replace(pair, sandbox_id=uuid4()), replace(pair, generation=uuid4()))
        for role in ("guest-relay", "egress-relay")
    }
    assert len(names) == 6
    assert all(
        len(name) <= 253 and all(len(label) <= 63 for label in name.split(".")) for name in names
    )


def test_builders_do_not_mutate_platform_objects(object_settings, pair, runtime):
    previous = deepcopy(object_settings)
    pod = relay_pod(object_settings, pair, "guest-relay", runtime)
    pod["spec"]["nodeSelector"]["foreign"] = "value"
    pod["spec"]["tolerations"].clear()
    container = pod["spec"]["containers"][0]
    container["resources"]["requests"]["cpu"] = "9"
    assert container["resources"]["limits"]["cpu"] == "1000m"
    assert object_settings == previous
    assert (
        relay_pod(object_settings, pair, "guest-relay", runtime)["spec"]["nodeSelector"]
        == previous.node_selector
    )


@pytest.mark.parametrize("role", ["guest", "egress", "ipc", "../guest-relay"])
def test_invalid_role_cannot_select_arbitrary_input_or_pod(object_settings, pair, runtime, role):
    with pytest.raises(ValueError, match="role"):
        relay_input_name(pair, role)
    with pytest.raises(ValueError, match="role"):
        relay_pod(object_settings, pair, role, runtime)
    with pytest.raises(ValueError, match="role"):
        relay_configuration(pair, role, uuid4(), PEER_KEY, runtime)


@pytest.mark.parametrize(
    "field,value",
    [
        ("image", ""),
        ("image", "registry.test/relay:latest"),
        ("image", "relay@sha256:bad"),
        ("image", None),
        ("tls_secret", ""),
        ("tls_secret", "Bad"),
        ("tls_secret", "../key"),
        ("tls_secret", "a..b"),
        ("tls_secret", "a" * 64),
        ("tls_secret", None),
        ("transport_mtu", 685),
        ("transport_mtu", 65536),
        ("transport_mtu", True),
        ("packet_rate", 99),
        ("packet_rate", 100001),
        ("packet_rate", "10000"),
        ("cpu_millis", 0),
        ("cpu_millis", 64001),
        ("cpu_millis", False),
        ("memory_mib", 31),
        ("memory_mib", 65537),
        ("memory_mib", 256.0),
        ("startup_seconds", 14),
        ("startup_seconds", 301),
        ("startup_seconds", None),
    ],
)
def test_invalid_platform_inputs_are_rejected(runtime, field, value):
    with pytest.raises(ValueError):
        replace(runtime, **{field: value})


@pytest.mark.parametrize("uid", [None, "", str(uuid4()), 1])
def test_only_observed_uuid_type_can_bind_configuration(pair, runtime, uid):
    with pytest.raises(ValueError, match="UID"):
        relay_configuration(pair, "guest-relay", uid, PEER_KEY, runtime, "10.32.0.99")


@pytest.mark.parametrize(
    "key", [None, "", "bad", PEER_KEY + "\n", b"a" * 32, base64.b64encode(bytes(32)).decode()]
)
def test_invalid_peer_key_rejected_without_echoing_it(pair, runtime, key):
    with pytest.raises(ValueError, match="invalid relay peer public key"):
        relay_configuration(pair, "guest-relay", uuid4(), key, runtime, "10.32.0.99")


@pytest.mark.parametrize(
    "address",
    [
        None,
        "",
        "service.test",
        "::1",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "169.254.1.1",
        "255.255.255.255",
        "10.032.0.1",
    ],
)
def test_guest_endpoint_requires_numeric_observed_service_address(pair, runtime, address):
    with pytest.raises(ValueError):
        relay_configuration(pair, "guest-relay", uuid4(), PEER_KEY, runtime, address)


def test_egress_never_uses_configured_endpoint_and_tls_cannot_alias_transport(
    object_settings, pair, runtime
):
    with pytest.raises(ValueError, match="authenticated"):
        relay_configuration(pair, "egress-relay", uuid4(), PEER_KEY, runtime, "10.32.0.99")
    with pytest.raises(ValueError, match="separate"):
        relay_pod(
            object_settings,
            pair,
            "guest-relay",
            replace(runtime, tls_secret=relay_input_name(pair, "guest-relay")),
        )
