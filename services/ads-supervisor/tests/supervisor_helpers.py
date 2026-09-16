from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import msgspec

from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    DecisionRequest,
    Placement,
    PolicyDecision,
    Run,
    RunRequest,
    ToolCallRequest,
)
from ads_policy.service import PolicyService
from ads_supervisor.supervisor import Sandbox

TOKEN = "supervisor-api-token-32-bytes"
GOVERNANCE = GovernanceSettings()

#: A Kata pod on a sandbox node, as the launcher that created it describes it.
VM_SANDBOX = Sandbox(
    project="ads",
    repo="yet-another-solutions/ads",
    env="dev",
    workdir=GOVERNANCE.workdir,
    placement=Placement.CLUSTER,
    runtime_class_name=GOVERNANCE.vm_runtime_class,
    node_labels={
        GOVERNANCE.sandbox_node_label: GOVERNANCE.node_label_value,
        GOVERNANCE.application_node_label: GOVERNANCE.node_label_value,
    },
)
WORKSTATION = msgspec.structs.replace(
    VM_SANDBOX, placement=Placement.WORKSTATION, runtime_class_name=None, node_labels={}
)


def sandbox_body(sandbox: Sandbox = VM_SANDBOX) -> dict[str, Any]:
    return dict(msgspec.to_builtins(sandbox))


def blocking[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """The supervisor is synchronous, so the policy service runs on a loop of its own."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()


class DirectPolicyClient:
    """The policy service without the network, for tests that are not about transport."""

    def __init__(self, service: PolicyService) -> None:
        self.service = service

    def start_run(self, request: RunRequest) -> Run:
        return blocking(self.service.start(request))

    def revoke_run(self, run_id: str) -> Run:
        run = blocking(self.service.revoke(run_id))
        if run is None:
            raise KeyError(run_id)
        return run

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        return blocking(self.service.decide(request))

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        return blocking(self.service.decide_call(call))


class RefusingPolicyClient:
    """Stands in for a policy service that cannot be reached at all."""

    def start_run(self, request: RunRequest) -> Run:
        raise ConnectionError("no route to the policy service")

    def revoke_run(self, run_id: str) -> Run:
        raise ConnectionError("no route to the policy service")

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        raise ConnectionError("no route to the policy service")

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        raise ConnectionError("no route to the policy service")
