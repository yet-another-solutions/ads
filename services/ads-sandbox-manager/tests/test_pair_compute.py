# ruff: noqa: F811
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from uuid import uuid4

import pytest

from ads_sandbox_manager.pair_compute import PrivateGuestRuntime, private_guest_pod
from ads_sandbox_manager.pair_objects import compute_identity, placement
from ads_sandbox_manager.session_objects import ca_consumer_name, guest_deployment, session_name
from test_pair_objects import pair  # noqa: F401
from test_session_objects import object_settings  # noqa: F401


@pytest.fixture
def guest_inputs(object_settings, pair):
    return object_settings, pair, uuid4(), uuid4(), PrivateGuestRuntime("private-guest", 1450)


def test_private_guest_is_fixed_pod_not_workload_controller(guest_inputs):
    settings, pair, pvc, attempt, runtime = guest_inputs
    pod = private_guest_pod(*guest_inputs)
    assert {k: v for k, v in pod.items() if k != "spec"} == compute_identity(
        settings, pair, "guest"
    )
    spec = pod["spec"]
    assert spec["runtimeClassName"] == runtime.runtime_class
    assert spec["schedulingGroup"] == placement(pair, "guest")["schedulingGroup"]
    assert spec["restartPolicy"] == "Never"
    assert spec["terminationGracePeriodSeconds"] == 30
    assert not spec["automountServiceAccountToken"] and not spec["enableServiceLinks"]
    assert spec["nodeSelector"] == settings.node_selector
    assert spec["tolerations"] == settings.tolerations
    assert spec["imagePullSecrets"] == [{"name": x} for x in settings.image_pull_secrets]
    assert spec["dnsPolicy"] == "None" and spec["dnsConfig"] == {"nameservers": ["10.10.30.1"]}
    assert len(spec["containers"]) == 1
    assert not {"hostNetwork", "hostPID", "hostIPC", "initContainers", "nodeName"} & spec.keys()
    assert "ownerReferences" not in pod["metadata"]
    assert spec["volumes"] == [
        {"name": "session", "persistentVolumeClaim": {"claimName": session_name(pvc)}},
        {
            "name": "ca-public",
            "persistentVolumeClaim": {
                "claimName": ca_consumer_name(pair.sandbox_id, "guest"),
                "readOnly": True,
            },
        },
    ]
    container = spec["containers"][0]
    assert container["name"] == "sandbox"
    assert container["image"] == settings.session_objects.guest_image
    assert (
        not {"command", "args", "envFrom", "volumeMounts", "ports", "livenessProbe"}
        & container.keys()
    )
    assert container["resources"] == settings.session_objects.guest_resources
    assert container["securityContext"] == {
        "runAsUser": 0,
        "runAsGroup": 0,
        "privileged": False,
        "allowPrivilegeEscalation": True,
        "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]},
    }
    assert container["volumeDevices"] == [
        {"name": "session", "devicePath": "/dev/ads-session"},
        {"name": "ca-public", "devicePath": "/dev/ads-ca-public"},
    ]
    env = {entry["name"]: entry["value"] for entry in container["env"]}
    assert len(env) == len(container["env"])
    assert env == {
        "ADS_SESSION_DEVICE": "/dev/ads-session",
        "ADS_CA_ATTEMPT": str(attempt),
        "ADS_SANDBOX_NETWORK_MODE": "private",
        "ADS_SANDBOX_ID": str(pair.sandbox_id),
        "ADS_ATTACHMENT_GENERATION": str(pair.generation),
        "ADS_PRIVATE_MTU": "1340",
        **{
            f"ADS_SANDBOX_{key}": str(value)
            for key, value in settings.session_objects.guest_budget.items()
        },
    }
    assert container["readinessProbe"] == {
        "exec": {"command": ["test", "-f", "/run/ads-sandbox-ready"]},
        "periodSeconds": 2,
    }
    assert not any("secret" in volume or "hostPath" in volume for volume in spec["volumes"])
    assert "ads-ca-key" not in str(pod)


def test_builder_does_not_mutate_inputs_or_legacy_boot(guest_inputs):
    settings, pair, pvc, attempt, runtime = guest_inputs
    before = deepcopy(settings)
    legacy = guest_deployment(
        settings, pair.session_id, pair.sandbox_id, settings.golden_version, pvc, attempt
    )
    first = private_guest_pod(*guest_inputs)
    first["spec"]["nodeSelector"]["foreign"] = "value"
    first["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "100"
    first["spec"]["tolerations"].clear()
    second = private_guest_pod(*guest_inputs)
    assert settings == before
    assert second["spec"]["nodeSelector"] == settings.node_selector
    assert second["spec"]["containers"][0]["resources"] == settings.session_objects.guest_resources
    assert legacy == guest_deployment(
        settings, pair.session_id, pair.sandbox_id, settings.golden_version, pvc, attempt
    )
    assert legacy["spec"]["template"]["spec"]["runtimeClassName"] != runtime.runtime_class
    with pytest.raises(FrozenInstanceError):
        runtime.transport_mtu = 1500


@pytest.mark.parametrize("field", ["generation", "sandbox_id", "session_id", "project_id"])
def test_pair_identity_changes_are_reflected_in_fixed_pod(guest_inputs, field):
    settings, pair, pvc, attempt, runtime = guest_inputs
    changed = replace(pair, **{field: uuid4()})
    pod = private_guest_pod(settings, changed, pvc, attempt, runtime)
    assert pod["metadata"] == compute_identity(settings, changed, "guest")["metadata"]
    assert pod["metadata"] != private_guest_pod(*guest_inputs)["metadata"]
    assert pod["spec"]["schedulingGroup"] == placement(changed, "guest")["schedulingGroup"]
    env = {e["name"]: e["value"] for e in pod["spec"]["containers"][0]["env"]}
    assert env["ADS_ATTACHMENT_GENERATION"] == str(changed.generation)


@pytest.mark.parametrize("value", [None, False, "", "A", "-private", "private-", "a.b", "a" * 64])
def test_private_runtime_class_must_be_explicit_dns_label(value):
    with pytest.raises(ValueError, match="RuntimeClass"):
        PrivateGuestRuntime(value, 1450)


@pytest.mark.parametrize("mtu", [None, True, 1450.0, "1450", 0, 685, 65536])
def test_mtu_is_exact_bounded_platform_input(mtu):
    with pytest.raises(ValueError, match="MTU"):
        PrivateGuestRuntime("private-guest", mtu)


@pytest.mark.parametrize("mtu", [686, 1450, 1500, 65535])
def test_private_mtu_matches_attestor_encapsulation_contract(guest_inputs, mtu):
    settings, pair, pvc, attempt, runtime = guest_inputs
    pod = private_guest_pod(settings, pair, pvc, attempt, replace(runtime, transport_mtu=mtu))
    env = {e["name"]: e["value"] for e in pod["spec"]["containers"][0]["env"]}
    assert int(env["ADS_PRIVATE_MTU"]) == mtu - 110


@pytest.mark.parametrize("field", ["pvc", "attempt"])
@pytest.mark.parametrize("value", [None, "", "project-input", str(uuid4())])
def test_committed_ids_cannot_be_replaced_by_strings(guest_inputs, field, value):
    settings, pair, pvc, attempt, runtime = guest_inputs
    with pytest.raises(ValueError, match="identities"):
        private_guest_pod(
            settings,
            pair,
            value if field == "pvc" else pvc,
            value if field == "attempt" else attempt,
            runtime,
        )


def test_no_fallback_to_legacy_runtime_or_missing_settings(guest_inputs):
    settings, pair, pvc, attempt, runtime = guest_inputs
    with pytest.raises(ValueError, match="distinct private-only"):
        private_guest_pod(
            settings,
            pair,
            pvc,
            attempt,
            replace(runtime, runtime_class=settings.session_objects.guest_runtime_class),
        )
    with pytest.raises(ValueError, match="session settings"):
        private_guest_pod(replace(settings, session_objects=None), pair, pvc, attempt, runtime)
