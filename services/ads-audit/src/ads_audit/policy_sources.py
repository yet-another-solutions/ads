from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

import anyio.to_thread

from ads_policy.client import HttpPolicyClient, PolicyUnavailable
from ads_policy.contract import SourceChecks


class PolicySources(Protocol):
    async def sources(self) -> Sequence[SourceChecks]: ...


@dataclass(frozen=True, slots=True, eq=False)
class HttpPolicySources:
    client: HttpPolicyClient

    async def sources(self) -> Sequence[SourceChecks]:
        return await anyio.to_thread.run_sync(self.client.sources)


class UnconfiguredPolicySources:
    async def sources(self) -> Sequence[SourceChecks]:
        raise PolicyUnavailable("policy service is not configured")
