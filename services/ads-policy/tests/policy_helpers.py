from __future__ import annotations

from collections.abc import Mapping

from ads_policy.config import PlacementRules, ResourceNaming
from ads_policy.contract import (
    Capability,
    DecisionRequest,
    IsolationLevel,
    Placement,
    PolicyRequest,
    RunContext,
    RunRequest,
)

NAMING = ResourceNaming()
PLACEMENT = PlacementRules()
ATTRIBUTES = {"repo.write": "true", "agent": "true"}


def run_context(**overrides: str) -> RunContext:
    values = {
        "project": "ads",
        "repo": "yet-another-solutions/ads",
        "env": "dev",
        "workdir": NAMING.workdir,
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


def run_request(level: IsolationLevel, subject: str = "alice", holder: str = "") -> RunRequest:
    labels: dict[str, str] = {}
    runtime: str | None = None
    placement = Placement.CLUSTER
    if level is IsolationLevel.CONTAINER:
        labels = {PLACEMENT.application_node_label: PLACEMENT.node_label_value}
    elif level is IsolationLevel.VM:
        labels = {
            PLACEMENT.sandbox_node_label: PLACEMENT.node_label_value,
            PLACEMENT.application_node_label: PLACEMENT.node_label_value,
        }
        runtime = PLACEMENT.vm_runtime_class
    else:
        placement = Placement.WORKSTATION
    return RunRequest(
        subject=subject,
        project="ads",
        repo="yet-another-solutions/ads",
        env="dev",
        workdir=NAMING.workdir,
        placement=placement,
        runtime_class_name=runtime,
        node_labels=labels,
        holder=holder,
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
