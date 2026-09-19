from __future__ import annotations

import pytest

from ads_policy.config import PlacementRules
from ads_policy.contract import IsolationLevel, Placement
from ads_policy.isolation import (
    RuntimeProfile,
    UnknownPlacement,
    assign_isolation_level,
    at_least,
    parse_isolation_level,
    runtime_profile,
)

SETTINGS = PlacementRules()


def test_kata_runtime_on_a_sandbox_node_is_vm() -> None:
    level = assign_isolation_level(
        runtime_class_name=SETTINGS.vm_runtime_class,
        node_labels={SETTINGS.sandbox_node_label: SETTINGS.node_label_value},
    )
    assert level is IsolationLevel.VM


def test_application_node_without_runtime_class_is_container() -> None:
    level = assign_isolation_level(
        node_labels={SETTINGS.application_node_label: SETTINGS.node_label_value},
    )
    assert level is IsolationLevel.CONTAINER


def test_unconfirmed_placement_opens_no_run() -> None:
    for kwargs in ({}, {"node_labels": {}}, {"runtime_class_name": "runc"}):
        with pytest.raises(UnknownPlacement):
            assign_isolation_level(**kwargs)  # type: ignore[arg-type]


def test_local_is_asserted_by_whoever_opens_the_run_not_derived() -> None:
    level = assign_isolation_level(placement=Placement.WORKSTATION)
    assert level is IsolationLevel.LOCAL


def test_a_workstation_owes_no_cluster_placement() -> None:
    level = assign_isolation_level(
        placement=Placement.WORKSTATION,
        runtime_class_name=SETTINGS.vm_runtime_class,
        node_labels={SETTINGS.sandbox_node_label: SETTINGS.node_label_value},
    )
    assert level is IsolationLevel.LOCAL


def test_a_cluster_without_a_sandbox_cannot_produce_a_vm() -> None:
    without = PlacementRules(sandbox_available=False)
    level = assign_isolation_level(
        runtime_class_name=SETTINGS.vm_runtime_class,
        node_labels={
            SETTINGS.sandbox_node_label: SETTINGS.node_label_value,
            SETTINGS.application_node_label: SETTINGS.node_label_value,
        },
        settings=without,
    )
    assert level is IsolationLevel.CONTAINER


def test_kata_without_sandbox_label_is_not_vm() -> None:
    level = assign_isolation_level(
        runtime_class_name=SETTINGS.vm_runtime_class,
        node_labels={SETTINGS.application_node_label: SETTINGS.node_label_value},
    )
    assert level is IsolationLevel.CONTAINER


def test_sandbox_label_without_kata_is_not_vm() -> None:
    level = assign_isolation_level(
        node_labels={
            SETTINGS.sandbox_node_label: SETTINGS.node_label_value,
            SETTINGS.application_node_label: SETTINGS.node_label_value,
        },
    )
    assert level is IsolationLevel.CONTAINER


def test_an_unreadable_level_is_no_level() -> None:
    assert parse_isolation_level("vm") is IsolationLevel.VM
    assert parse_isolation_level("vm-please") is None
    assert parse_isolation_level(None) is None
    assert parse_isolation_level(2) is None


def test_levels_are_ordered() -> None:
    assert at_least(IsolationLevel.VM, IsolationLevel.CONTAINER)
    assert at_least(IsolationLevel.CONTAINER, IsolationLevel.CONTAINER)
    assert not at_least(IsolationLevel.LOCAL, IsolationLevel.CONTAINER)


def test_runtime_profile_round_trips_back_to_the_level() -> None:
    for level in (IsolationLevel.CONTAINER, IsolationLevel.VM):
        profile = runtime_profile(level)
        assert (
            assign_isolation_level(
                runtime_class_name=profile.runtime_class_name,
                node_labels=profile.node_selector,
            )
            is level
        )


def test_local_profile_schedules_nothing() -> None:
    profile = runtime_profile(IsolationLevel.LOCAL)
    assert profile.runtime_class_name is None
    assert profile.node_selector == {}


def test_profile_is_the_only_difference_between_levels() -> None:
    assert set(RuntimeProfile.__dataclass_fields__) == {"runtime_class_name", "node_selector"}
    container = runtime_profile(IsolationLevel.CONTAINER)
    vm = runtime_profile(IsolationLevel.VM)
    assert container.runtime_class_name != vm.runtime_class_name
    assert container.node_selector != vm.node_selector
