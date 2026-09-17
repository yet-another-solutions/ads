from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from ads_policy.config import GovernanceSettings
from ads_policy.contract import IsolationLevel, Placement

_RANK: Mapping[IsolationLevel, int] = {
    IsolationLevel.LOCAL: 0,
    IsolationLevel.CONTAINER: 1,
    IsolationLevel.VM: 2,
}


def at_least(level: IsolationLevel, minimum: IsolationLevel) -> bool:
    return _RANK[level] >= _RANK[minimum]


class UnknownPlacement(ValueError):
    pass


def parse_isolation_level(value: object) -> IsolationLevel | None:
    if isinstance(value, IsolationLevel):
        return value
    if isinstance(value, str):
        try:
            return IsolationLevel(value)
        except ValueError:
            return None
    return None


def assign_isolation_level(
    *,
    placement: Placement = Placement.CLUSTER,
    runtime_class_name: str | None = None,
    node_labels: Mapping[str, str] | None = None,
    settings: GovernanceSettings | None = None,
) -> IsolationLevel:
    config = settings or GovernanceSettings()
    if placement is Placement.WORKSTATION:
        return IsolationLevel.LOCAL
    labels = node_labels or {}
    on_sandbox_node = labels.get(config.sandbox_node_label) == config.node_label_value
    runs_under_kata = runtime_class_name in config.kata_runtime_classes
    if config.sandbox_available and runs_under_kata and on_sandbox_node:
        return IsolationLevel.VM
    on_application_node = labels.get(config.application_node_label) == config.node_label_value
    if on_application_node or on_sandbox_node:
        return IsolationLevel.CONTAINER
    raise UnknownPlacement(
        f"no node carries {config.application_node_label}={config.node_label_value}"
        f" or {config.sandbox_node_label}={config.node_label_value}"
    )


@dataclass(frozen=True, slots=True)
class RuntimeProfile:
    runtime_class_name: str | None = None
    node_selector: Mapping[str, str] = field(default_factory=dict)


def runtime_profile(
    level: IsolationLevel, settings: GovernanceSettings | None = None
) -> RuntimeProfile:
    config = settings or GovernanceSettings()
    if level is IsolationLevel.VM:
        return RuntimeProfile(
            runtime_class_name=config.vm_runtime_class,
            node_selector={config.sandbox_node_label: config.node_label_value},
        )
    if level is IsolationLevel.CONTAINER:
        return RuntimeProfile(
            node_selector={config.application_node_label: config.node_label_value}
        )
    return RuntimeProfile()
