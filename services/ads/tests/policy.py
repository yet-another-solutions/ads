from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ads_commons_web.security_context import SecurityContext
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.config import PlacementRules, ResourceNaming
from ads_policy.contract import (
    DecisionRequest,
    IsolationLevel,
    Placement,
    PolicyDecision,
    Run,
    RunRequest,
    ToolCallRequest,
)
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy
from ads_policy.run import InMemoryRunStore
from ads_policy.service import PolicyService

PLACEMENT = PlacementRules()
NAMING = ResourceNaming()
ATTRIBUTES = {"repo.write": "true", "agent": "true"}


def _blocking[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """The enforcer is synchronous, so the service runs on a loop of its own."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()


class DirectPolicyClient:
    """The policy service without the network, for tests that are not about transport."""

    def __init__(self, service: PolicyService) -> None:
        self.service = service

    def start_run(self, request: RunRequest) -> Run:
        return _blocking(self.service.start(request))

    def run(self, run_id: str) -> Run | None:
        return _blocking(self.service.run(run_id))

    def runs_held(self, holder: str) -> list[Run]:
        return _blocking(self.service.held_by(holder))

    def finish_run(self, run_id: str) -> Run | None:
        return _blocking(self.service.finish(run_id))

    def revoke_run(self, run_id: str) -> Run:
        run = _blocking(self.service.revoke(run_id))
        if run is None:
            raise KeyError(run_id)
        return run

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        return _blocking(self.service.decide(request))

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        return _blocking(self.service.decide_call(call))


def policy_service(journal: CollectingAuditSink) -> PolicyService:
    return PolicyService(
        PolicyDecisionPoint(org_policy()), InMemoryRunStore(), BufferedAuditSink(journal)
    )


def journalled(service: PolicyService) -> int:
    """How many decisions the service has handed to the audit exchange."""
    return _blocking(service.flush_audit())


def run_request(level: IsolationLevel, subject: str = "alice") -> RunRequest:
    """Ask for a run the way a controller would, by describing the placement."""
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
    )


def security_context(*roles: str) -> SecurityContext:
    return SecurityContext(subject="alice", name="Alice", roles=frozenset(roles))
