from __future__ import annotations

import json
from copy import deepcopy
from uuid import uuid4

import msgspec
import pytest

from ads_commons.sandbox.node_release import decode_node_release


@pytest.fixture
def node_report():
    return {
        "schema": "ads-node-release-v1",
        "node": "worker",
        "namespace": "sandboxes",
        "network": "ads-private",
        "generation": str(uuid4()),
        "sandbox_id": str(uuid4()),
        "boot_id": str(uuid4()),
        "pod_uids": [str(uuid4()) for _ in range(4)],
        "inventory_sha256": "a" * 64,
        "attachment_admission_fenced": True,
        "release_inventory_captured": True,
        "observed_runtime_released": False,
        "generation_retired": False,
        "leftovers": None,
    }


def clear_counts():
    return dict.fromkeys(
        (
            "pods",
            "ready_sandboxes",
            "live_containers",
            "journals",
            "host_links",
            "process_namespace_references",
        ),
        0,
    )


def raw(value):
    return json.dumps(value).encode()


def test_capture_and_positive_negative_observation_roundtrip(node_report):
    capture = decode_node_release(raw(node_report))
    assert capture.leftovers is None and not capture.observed_runtime_released
    observed = {**node_report, "leftovers": clear_counts(), "observed_runtime_released": True}
    assert decode_node_release(raw(observed)).observed_runtime_released
    for field in clear_counts():
        blocked = deepcopy(observed)
        blocked["leftovers"][field] = 1
        blocked["observed_runtime_released"] = False
        assert not decode_node_release(raw(blocked)).observed_runtime_released


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "v0"),
        ("node", ""),
        ("namespace", None),
        ("network", "x" * 254),
        ("generation", "bad"),
        ("sandbox_id", 3),
        ("boot_id", ""),
        ("pod_uids", []),
        ("inventory_sha256", "A" * 64),
        ("inventory_sha256", "b" * 63),
        ("inventory_sha256", "b" * 64 + "\n"),
        ("attachment_admission_fenced", False),
        ("attachment_admission_fenced", 1),
        ("release_inventory_captured", False),
        ("observed_runtime_released", True),
        ("generation_retired", True),
        ("leftovers", {}),
        ("extra", "rejected"),
    ],
)
def test_malformed_or_inconsistent_reports_rejected(node_report, field, value):
    with pytest.raises((ValueError, msgspec.ValidationError)):
        decode_node_release(raw({**node_report, field: value}))


def test_duplicate_pods_fields_and_unbounded_payloads_rejected(node_report):
    duplicate = {**node_report, "pod_uids": [node_report["pod_uids"][0]] * 4}
    with pytest.raises(ValueError):
        decode_node_release(raw(duplicate))
    for payload in (b"", b" " * 16385, raw(node_report)[:-1] + b',"node":"worker"}'):
        with pytest.raises(ValueError):
            decode_node_release(payload)


@pytest.mark.parametrize("count", [-1, True, 0.0, 2147483648, "0"])
def test_count_types_and_bounds_fail_closed(node_report, count):
    counters = clear_counts()
    counters["pods"] = count
    with pytest.raises(ValueError):
        decode_node_release(raw({**node_report, "leftovers": counters}))


def test_incomplete_or_forged_clear_observation_is_rejected(node_report):
    for counts in ({**clear_counts(), "extra": 0}, {"pods": 0}):
        with pytest.raises(ValueError):
            decode_node_release(raw({**node_report, "leftovers": counts}))
    with pytest.raises(ValueError):
        decode_node_release(raw({**node_report, "leftovers": clear_counts()}))
    observed = {
        **node_report,
        "leftovers": {**clear_counts(), "journals": 1},
        "observed_runtime_released": True,
    }
    with pytest.raises(ValueError):
        decode_node_release(raw(observed))
