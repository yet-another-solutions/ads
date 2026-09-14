from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ads_policy.contract import DecisionRequest, PolicyDecision, Run, RunRequest
from ads_policy.service import PolicyService

TOKEN = "supervisor-api-token-32-bytes"


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


class RefusingPolicyClient:
    """Stands in for a policy service that cannot be reached at all."""

    def start_run(self, request: RunRequest) -> Run:
        raise ConnectionError("no route to the policy service")

    def revoke_run(self, run_id: str) -> Run:
        raise ConnectionError("no route to the policy service")

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        raise ConnectionError("no route to the policy service")
