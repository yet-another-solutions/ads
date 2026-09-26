# ruff: noqa: F811
from copy import deepcopy
from uuid import uuid4

import pytest

from ads_sandbox_manager.egress_compute import egress_pod
from ads_sandbox_manager.pair_compute_kube import PairComputeAdapter
from test_egress_compute import object_settings, runtime, state  # noqa: F401
from test_pair_objects import pair  # noqa: F401
from test_session_objects import object_settings as base_settings  # noqa: F401


@pytest.fixture
def desired(object_settings, pair, state, runtime):
    return egress_pod(object_settings, pair, uuid4(), state, runtime)


@pytest.mark.parametrize("omitted", [False, True])
def test_egress_runtime_mount_accepts_only_exact_false_default(desired, omitted):
    observed = deepcopy(desired)
    if omitted:
        del observed["spec"]["containers"][0]["volumeMounts"][0]["readOnly"]
    before = deepcopy((observed, desired))
    assert PairComputeAdapter._spec_matches(observed, desired)
    assert (observed, desired) == before


@pytest.mark.parametrize("value", [True, None, 0, 1, "", "false", "true", [], {}])
def test_writable_mount_rejects_changed_or_nonboolean_readonly(desired, value):
    observed = deepcopy(desired)
    observed["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = value
    assert not PairComputeAdapter._spec_matches(observed, desired)


def test_readonly_mount_requires_explicit_true(desired):
    desired["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = True
    assert PairComputeAdapter._spec_matches(deepcopy(desired), desired)
    observed = deepcopy(desired)
    del observed["spec"]["containers"][0]["volumeMounts"][0]["readOnly"]
    assert not PairComputeAdapter._spec_matches(observed, desired)


@pytest.mark.parametrize("value", [False, None, 0, 1, "", "true", [], {}])
def test_readonly_mount_never_becomes_writable_or_accepts_lookalikes(desired, value):
    desired["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = True
    observed = deepcopy(desired)
    observed["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = value
    assert not PairComputeAdapter._spec_matches(observed, desired)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "different-volume"),
        ("mountPath", "/etc"),
        ("subPath", "different-path"),
        ("mountPropagation", "Bidirectional"),
    ],
)
def test_default_normalization_does_not_allow_other_mount_changes(desired, field, value):
    observed = deepcopy(desired)
    mount = observed["spec"]["containers"][0]["volumeMounts"][0]
    del mount["readOnly"]
    mount[field] = value
    assert not PairComputeAdapter._spec_matches(observed, desired)


@pytest.mark.parametrize("change", ["missing", "extra", "malformed"])
def test_default_normalization_keeps_exact_mount_membership(desired, change):
    observed = deepcopy(desired)
    mounts = observed["spec"]["containers"][0]["volumeMounts"]
    if change == "missing":
        mounts.clear()
    elif change == "extra":
        mounts.append({"name": "extra", "mountPath": "/extra"})
    else:
        mounts[0] = None
    assert not PairComputeAdapter._spec_matches(observed, desired)


def test_runtime_mount_default_does_not_relax_ca_volume_readonly(desired):
    observed = deepcopy(desired)
    del observed["spec"]["containers"][0]["volumeMounts"][0]["readOnly"]
    ca = next(v for v in observed["spec"]["volumes"] if v["name"] == "ca-private")
    assert ca["persistentVolumeClaim"]["readOnly"] is True
    ca["persistentVolumeClaim"]["readOnly"] = False
    assert not PairComputeAdapter._spec_matches(observed, desired)
