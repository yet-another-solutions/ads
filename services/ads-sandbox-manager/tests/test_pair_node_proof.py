# ruff: noqa: F811
from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ads_sandbox_manager.pair_node_proof import capture_report, release_report
from ads_sandbox_manager.pair_objects import PairBinding
from test_node_release_wire import clear_counts, node_report, raw  # noqa: F401


def capture(value, **overrides):
    arguments = {
        "node": value["node"],
        "namespace": value["namespace"],
        "network": value["network"],
        "pod_uids": dict(
            zip(
                ("Pod/guest", "Pod/egress", "Pod/guest-relay", "Pod/egress-relay"),
                value["pod_uids"],
                strict=True,
            )
        ),
    }
    pair = PairBinding(uuid4(), UUID(value["sandbox_id"]), uuid4(), UUID(value["generation"]))
    return capture_report(raw(value), pair, **{**arguments, **overrides})


def test_exact_capture_and_release_binding(node_report):
    captured = capture(node_report)
    observation = {**node_report, "leftovers": clear_counts(), "observed_runtime_released": True}
    assert release_report(raw(observation), captured)
    observation["pod_uids"] = list(reversed(observation["pod_uids"]))
    assert release_report(raw(observation), captured)
    observation["leftovers"]["process_namespace_references"] = 1
    observation["observed_runtime_released"] = False
    assert not release_report(raw(observation), captured)


@pytest.mark.parametrize("field", ["node", "namespace", "network"])
def test_capture_refuses_wrong_node_placement_or_scope(node_report, field):
    with pytest.raises(ValueError):
        capture(node_report, **{field: "other"})


@pytest.mark.parametrize("field", ["generation", "sandbox_id"])
def test_capture_refuses_wrong_original_pair(node_report, field):
    pair = PairBinding(
        uuid4(),
        uuid4() if field == "sandbox_id" else UUID(node_report["sandbox_id"]),
        uuid4(),
        uuid4() if field == "generation" else UUID(node_report["generation"]),
    )
    with pytest.raises(ValueError, match="cleanup ownership"):
        capture_report(
            raw(node_report),
            pair,
            node=node_report["node"],
            namespace=node_report["namespace"],
            network=node_report["network"],
            pod_uids=dict(
                zip(
                    ("Pod/guest", "Pod/egress", "Pod/guest-relay", "Pod/egress-relay"),
                    node_report["pod_uids"],
                    strict=True,
                )
            ),
        )


@pytest.mark.parametrize("fault", ["missing", "unknown", "duplicate", "foreign", "invalid"])
def test_exact_four_pod_identities_are_mandatory(node_report, fault):
    uids = dict(
        zip(
            ("Pod/guest", "Pod/egress", "Pod/guest-relay", "Pod/egress-relay"),
            node_report["pod_uids"],
            strict=True,
        )
    )
    if fault == "missing":
        del uids["Pod/egress"]
    else:
        uids["Pod/egress"] = {
            "unknown": None,
            "duplicate": uids["Pod/guest"],
            "foreign": str(uuid4()),
            "invalid": "bad",
        }[fault]
    with pytest.raises(ValueError):
        capture(node_report, pod_uids=uids)


@pytest.mark.parametrize(
    "field",
    [
        "node",
        "namespace",
        "network",
        "generation",
        "sandbox_id",
        "boot_id",
        "inventory_sha256",
        "pod_uids",
    ],
)
def test_release_cannot_switch_original_inventory(node_report, field):
    captured = capture(node_report)
    value = {**node_report, "leftovers": clear_counts(), "observed_runtime_released": True}
    if field in ("generation", "sandbox_id", "boot_id"):
        value[field] = str(uuid4())
    elif field == "inventory_sha256":
        value[field] = "b" * 64
    elif field == "pod_uids":
        value[field] = [str(uuid4()) for _ in range(4)]
    else:
        value[field] = "other"
    with pytest.raises(ValueError, match="changed captured"):
        release_report(raw(value), captured)


def test_capture_response_is_never_release_and_observation_cannot_replace_capture(node_report):
    captured = capture(node_report)
    with pytest.raises(ValueError):
        release_report(raw(node_report), captured)
    observed = {**node_report, "leftovers": clear_counts(), "observed_runtime_released": True}
    with pytest.raises(ValueError):
        capture(observed)
    from ads_commons.sandbox.node_release import decode_node_release

    with pytest.raises(ValueError):
        release_report(raw(observed), decode_node_release(raw(observed)))
