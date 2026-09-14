from __future__ import annotations

from collections.abc import Mapping

from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    DecisionRequest,
    IsolationLevel,
    Placement,
    PolicyRequest,
    RunContext,
    RunRequest,
)

SETTINGS = GovernanceSettings()
ATTRIBUTES = {"repo.write": "true", "agent": "true"}


def run_context(**overrides: str) -> RunContext:
    values = {
        "project": "ads",
        "repo": "yet-another-solutions/ads",
        "env": "dev",
        "workdir": SETTINGS.workdir,
    }
    values.update(overrides)
    return RunContext(**values)


def policy_request(
    capability: Capability,
    resource: str = "",
    *,
    level: IsolationLevel = IsolationLevel.LOCAL,
    subject: str = "alice",
    attributes: Mapping[str, str] | None = None,
    context: RunContext | None = None,
) -> PolicyRequest:
    return PolicyRequest(
        subject=subject,
        capability=capability,
        resource=resource,
        isolation_level=level,
        context=context or run_context(),
        attributes=dict(ATTRIBUTES if attributes is None else attributes),
    )


def run_request(level: IsolationLevel, subject: str = "alice") -> RunRequest:
    """Ask for a run the way a controller would, by describing the placement."""
    labels: dict[str, str] = {}
    runtime: str | None = None
    placement = Placement.CLUSTER
    if level is IsolationLevel.CONTAINER:
        labels = {SETTINGS.application_node_label: SETTINGS.node_label_value}
    elif level is IsolationLevel.VM:
        labels = {
            SETTINGS.sandbox_node_label: SETTINGS.node_label_value,
            SETTINGS.application_node_label: SETTINGS.node_label_value,
        }
        runtime = SETTINGS.vm_runtime_class
    else:
        placement = Placement.WORKSTATION
    return RunRequest(
        subject=subject,
        project="ads",
        repo="yet-another-solutions/ads",
        env="dev",
        workdir=SETTINGS.workdir,
        placement=placement,
        runtime_class_name=runtime,
        node_labels=labels,
    )


def decision_request(
    run_id: str, capability: Capability, resource: str, subject: str = "alice"
) -> DecisionRequest:
    return DecisionRequest(
        run_id=run_id,
        subject=subject,
        capability=capability,
        resource=resource,
        attributes=dict(ATTRIBUTES),
    )
