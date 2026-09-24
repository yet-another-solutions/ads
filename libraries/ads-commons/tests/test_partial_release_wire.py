from __future__ import annotations

import json
from copy import deepcopy
from uuid import uuid4

import pytest

from ads_commons.sandbox.node_release import decode_node_release
from ads_commons.sandbox.partial_release import decode_partial_release
from test_node_release_wire import clear_counts, node_report  # noqa: F401


@pytest.fixture
def partial_report(node_report):  # noqa: F811
    return {
        **node_report,
        "schema": "ads-partial-release-v1",
        "pod_uids": {"guest": node_report["pod_uids"][0]},
    }


def raw(value):
    return json.dumps(value).encode()


def test_partial_capture_and_each_observation_are_not_full_pair_proof(partial_report):
    captured = decode_partial_release(raw(partial_report))
    assert len(captured.pod_uids) == 1 and not captured.observed_runtime_released
    with pytest.raises(ValueError):
        decode_node_release(raw(partial_report))
    released = {**partial_report, "leftovers": clear_counts(), "observed_runtime_released": True}
    assert decode_partial_release(raw(released)).observed_runtime_released
    for field in clear_counts():
        blocked = deepcopy(released)
        blocked["leftovers"][field] = 1
        blocked["observed_runtime_released"] = False
        assert not decode_partial_release(raw(blocked)).observed_runtime_released


@pytest.mark.parametrize(
    "roles",
    [
        {},
        {"foreign": str(uuid4())},
        {"ipc": str(uuid4())},
        {"guest": "bad"},
        {"guest": str(uuid4()), "egress": None},
        [],
        [str(uuid4())] * 4,
    ],
)
def test_empty_foreign_or_malformed_member_map_rejected(partial_report, roles):
    with pytest.raises(ValueError):
        decode_partial_release(raw({**partial_report, "pod_uids": roles}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "ads-node-release-v1"),
        ("boot_id", "bad"),
        ("node", ""),
        ("inventory_sha256", "a" * 63),
        ("attachment_admission_fenced", False),
        ("release_inventory_captured", False),
        ("generation_retired", True),
        ("observed_runtime_released", True),
        ("leftovers", {}),
        ("extra", True),
    ],
)
def test_partial_invalid_or_forged_verdict_rejected(partial_report, field, value):
    with pytest.raises(ValueError):
        decode_partial_release(raw({**partial_report, field: value}))


def test_partial_duplicate_fields_uids_and_bounds_rejected(partial_report):
    uid = partial_report["pod_uids"]["guest"]
    for payload in (
        b"",
        b" " * 16385,
        raw({**partial_report, "pod_uids": {"guest": uid, "egress": uid}}),
        raw(partial_report)[:-1] + b',"node":"worker"}',
        raw(partial_report).replace(
            raw({"guest": uid}), ('{"guest":"' + uid + '","guest":"' + uid + '"}').encode()
        ),
    ):
        with pytest.raises(ValueError):
            decode_partial_release(payload)
