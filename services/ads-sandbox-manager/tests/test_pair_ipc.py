# ruff: noqa: F811
from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from ads_sandbox_manager.pair_ipc import paired_ipc_deployment
from ads_sandbox_manager.pair_objects import (
    control_ingress,
    ipc_pair_environment,
    pair_labels,
    pair_name,
    pair_selector,
)
from ads_sandbox_manager.session_objects import ipc_deployment
from test_pair_objects import pair  # noqa: F401
from test_session_objects import object_settings  # noqa: F401


def test_exact_ipc_handoff_preserves_baseline_authority_and_health(object_settings, pair):
    uid, subject = str(uuid4()), uuid4()
    baseline = ipc_deployment(
        object_settings, pair.session_id, pair.sandbox_id, object_settings.golden_version
    )
    paired = paired_ipc_deployment(object_settings, pair, uid, subject)
    labels = pair_labels(object_settings, pair, "ipc")
    assert paired["metadata"]["name"] == baseline["metadata"]["name"]
    assert paired["metadata"]["labels"] == labels
    assert paired["spec"]["selector"]["matchLabels"] == pair_selector(pair, "ipc")
    template = paired["spec"]["template"]
    assert template["metadata"]["labels"] == labels
    spec = template["spec"]
    assert "runtimeClassName" not in spec
    assert "schedulingGroup" not in spec
    assert paired["spec"]["replicas"] == 1
    assert paired["spec"]["strategy"] == {"type": "Recreate"}
    container = spec["containers"][0]
    env = {entry["name"]: entry["value"] for entry in container["env"]}
    assert len(env) == len(container["env"])
    handoff = {
        **ipc_pair_environment(object_settings, pair),
        "ADS_SANDBOX_IPC_ADS_SERVICE_SUBJECT": str(subject),
        "ADS_SANDBOX_IPC_GUEST_POD_NAME": pair_name(pair, "guest"),
        "ADS_SANDBOX_IPC_GUEST_POD_UID": uid,
        "ADS_SANDBOX_IPC_ATTACHMENT_GENERATION": str(pair.generation),
    }
    assert all(env[key] == value for key, value in handoff.items())
    for role in ("egress", "guest-relay", "egress-relay"):
        allowed = control_ingress(object_settings, pair, role)["spec"]["ingress"][0]["from"]
        assert allowed == [{"podSelector": {"matchLabels": pair_selector(pair, "ipc")}}]
        assert all(labels[k] == v for k, v in allowed[0]["podSelector"]["matchLabels"].items())
    # Aside from exact identity and explicit handoff, retain every existing
    # credential reference, resource, security, health, PID disk and TLS field.
    baseline["metadata"]["labels"] = labels
    baseline["spec"]["selector"]["matchLabels"] = pair_selector(pair, "ipc")
    baseline["spec"]["template"]["metadata"]["labels"] = labels
    baseline["spec"]["template"]["spec"]["containers"][0]["env"].extend(
        {"name": key, "value": value} for key, value in handoff.items()
    )
    assert paired == baseline
    assert not paired["metadata"].get("ownerReferences")
    assert not any("hostPath" in volume for volume in spec["volumes"])
    assert not any(
        "wrapping" in str(volume) or "ca-key" in str(volume) for volume in spec["volumes"]
    )


@pytest.mark.parametrize("uid", [None, "", " ", " uid ", 123])
def test_no_missing_or_ambiguous_guest_uid(object_settings, pair, uid):
    with pytest.raises(ValueError, match="Pod UID"):
        paired_ipc_deployment(object_settings, pair, uid, uuid4())


def test_missing_config_or_non_native_service_subject(object_settings, pair):
    with pytest.raises(ValueError, match="configuration"):
        paired_ipc_deployment(replace(object_settings, session_objects=None), pair, "uid", uuid4())
    with pytest.raises(ValueError, match="service subject"):
        paired_ipc_deployment(object_settings, pair, "uid", "client-name")


def test_generation_changes_selection_without_mutating_existing_manifest(object_settings, pair):
    first = paired_ipc_deployment(object_settings, pair, "original-uid", uuid4())
    replacement = paired_ipc_deployment(
        object_settings, replace(pair, generation=uuid4()), "replacement-uid", uuid4()
    )
    assert first["spec"]["selector"] != replacement["spec"]["selector"]
    assert first["metadata"]["name"] == replacement["metadata"]["name"]
    values = {
        v["name"]: v["value"] for v in first["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert values["ADS_SANDBOX_IPC_GUEST_POD_UID"] == "original-uid"
    assert values["ADS_SANDBOX_IPC_ATTACHMENT_GENERATION"] == str(pair.generation)
