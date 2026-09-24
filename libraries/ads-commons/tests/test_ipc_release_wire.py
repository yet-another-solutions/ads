from __future__ import annotations

from uuid import uuid4

import msgspec
import pytest

from ads_commons.sandbox.ipc_release import decode_ipc_release


@pytest.fixture
def ipc_report():
    return {
        "schema": "ads-ipc-release-v1",
        "node": "application",
        "namespace": "sandbox",
        "generation": str(uuid4()),
        "sandbox_id": str(uuid4()),
        "boot_id": str(uuid4()),
        "pod_uid": str(uuid4()),
        "volume_uid": str(uuid4()),
        "inventory_sha256": "a" * 64,
        "release_inventory_captured": True,
        "observed_runtime_released": False,
        "leftovers": None,
    }


def test_ipc_capture_and_positive_observation_have_distinct_verdicts(ipc_report):
    assert not decode_ipc_release(msgspec.json.encode(ipc_report)).observed_runtime_released
    ipc_report.update(
        observed_runtime_released=True,
        leftovers=dict.fromkeys(
            (
                "pods",
                "ready_sandboxes",
                "live_containers",
                "process_references",
                "mount_references",
            ),
            0,
        ),
    )
    assert decode_ipc_release(msgspec.json.encode(ipc_report)).observed_runtime_released
    ipc_report["leftovers"]["mount_references"] = 1
    with pytest.raises(ValueError):
        decode_ipc_release(msgspec.json.encode(ipc_report))
    ipc_report["observed_runtime_released"] = False
    assert not decode_ipc_release(msgspec.json.encode(ipc_report)).observed_runtime_released


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "ads-node-release-v1"),
        ("node", ""),
        ("pod_uid", "not-a-uid"),
        ("volume_uid", None),
        ("boot_id", "old"),
        ("inventory_sha256", "a" * 63),
        ("inventory_sha256", "A" * 64),
        ("release_inventory_captured", False),
        ("observed_runtime_released", True),
        ("extra", True),
    ],
)
def test_bad_ipc_report_rejected(ipc_report, field, value):
    ipc_report[field] = value
    with pytest.raises(ValueError):
        decode_ipc_release(msgspec.json.encode(ipc_report))


def test_duplicate_oversized_and_nonbytes_ipc_reports_rejected(ipc_report):
    raw = msgspec.json.encode(ipc_report)
    for value in (raw[:-1] + b',"node":"other"}', b" " * 16385, raw.decode(), b""):
        with pytest.raises(ValueError):
            decode_ipc_release(value)
