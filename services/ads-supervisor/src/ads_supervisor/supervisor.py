from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

import structlog

from ads_policy.audit import AuditBacklogFull, BufferedAuditSink, record
from ads_policy.client import UNREACHABLE, PolicyClient, unreachable
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    DecisionRequest,
    Effect,
    InterceptionPoint,
    PolicyDecision,
    Run,
    RunRequest,
)
from ads_policy.output import inspect_payload
from ads_supervisor.config import Settings

logger = structlog.get_logger("ads.supervisor")


def _payload(arguments: Mapping[str, str]) -> str:
    """What the call actually sends. Values only: an argument name is never a secret.

    Newline-joined so that two harmless values cannot run together into something that
    looks like one credential.
    """
    return "\n".join(arguments.values())


class RunNotOpen(RuntimeError):
    """Asked to decide before a run exists, which nothing is allowed to do."""


@dataclass(slots=True, eq=False)
class Supervisor:
    """The PEP: it holds the run, asks the PDP, and journals every answer.

    It sits outside the boundary the agent executes in, so the agent cannot reach it
    to silence it. Nothing here inspects the tool call beyond naming it: the decision
    is the policy service's, and this side only enforces and records.
    """

    settings: Settings
    client: PolicyClient
    audit: BufferedAuditSink
    governance: GovernanceSettings = field(default_factory=GovernanceSettings)
    run: Run | None = None

    def open(self) -> Run:
        """One supervisor serves one run, opened before anything is executed."""
        started = self.client.start_run(
            RunRequest(
                subject=self.settings.subject,
                project=self.settings.project,
                repo=self.settings.repo,
                env=self.settings.env,
                workdir=self.settings.workdir,
                placement=self.settings.placement,
                runtime_class_name=self.settings.runtime_class_name,
                node_labels=dict(self.settings.node_labels or {}),
            )
        )
        self.run = started
        logger.info("run opened", run_id=started.id, isolation_level=started.isolation_level.value)
        return started

    def permit(
        self, capability: Capability, resource: str, arguments: Mapping[str, str]
    ) -> PolicyDecision:
        """What answering opencode's ``permission.asked`` comes down to.

        The matrix decides first. Only a call it permits is going to happen, so only
        then is there an outbound payload worth reading — and a credential in it turns
        the permission into a refusal.
        """
        if self.run is None:
            raise RunNotOpen("no run has been opened")
        request = DecisionRequest(
            run_id=self.run.id,
            subject=self.run.subject,
            capability=capability,
            resource=resource,
            attributes=dict(self.settings.attributes or {}),
        )
        decision = self.client.decide(request)
        if decision.rule_id == UNREACHABLE:
            return self._journal(request, decision)
        # The policy service journalled its own answer; a second copy would read as a
        # second attempt and charge the budget twice.
        if not decision.permitted:
            return decision
        leak = inspect_payload(_payload(arguments), InterceptionPoint.REQUEST, self.governance)
        if leak.effect is Effect.DENY:
            # This one the policy service never saw, so nobody else will record it.
            return self._journal(request, leak)
        return decision

    def _journal(self, request: DecisionRequest, decision: PolicyDecision) -> PolicyDecision:
        try:
            self.audit.enqueue(record(request, decision))
        except AuditBacklogFull as exc:
            return unreachable(
                f"cannot journal the decision: {exc}", self.governance.denied_message
            )
        return decision

    async def flush_audit(self) -> int:
        return await self.audit.drain()
