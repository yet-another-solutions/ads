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
    """Raised when a cluster placement resolves to no level, so no run may open."""


def parse_isolation_level(value: object) -> IsolationLevel | None:
    """An unreadable level is no level. Callers decide what to do about it."""
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
    """Derive the level from where the run was scheduled, never from what it claims.

    ``local`` is not derivable here: node labels are a cluster notion and a developer
    machine has none. The supervisor asserts it instead, because only it knows it is a
    devcontainer. A cluster placement that resolves to nothing is a refusal, not a
    weaker level — weaker isolation is not the same as fewer permissions.

    A cluster without sandbox nodes cannot honour a Kata placement, so a run that
    claims one is still only a container, which is what it physically is.
    """
    config = settings or GovernanceSettings()
    if placement is Placement.WORKSTATION:
        return IsolationLevel.LOCAL
    labels = node_labels or {}
    sandbox = labels.get(config.sandbox_node_label) == config.node_label_value
    if config.sandbox_available and runtime_class_name in config.kata_runtime_classes and sandbox:
        return IsolationLevel.VM
    application = labels.get(config.application_node_label) == config.node_label_value
    if application or sandbox:
        return IsolationLevel.CONTAINER
    raise UnknownPlacement(
        f"no node carries {config.application_node_label}={config.node_label_value}"
        f" or {config.sandbox_node_label}={config.node_label_value}"
    )


@dataclass(frozen=True, slots=True)
class RuntimeProfile:
    """The whole physical difference between the levels: one field and one selector."""

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
