from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

import msgspec
import structlog

from ads_policy.audit import AuditBacklogFull, BufferedAuditSink
from ads_policy.client import UNREACHABLE, PolicyClient, unreachable
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    AuditEvent,
    Effect,
    InterceptionPoint,
    PolicyDecision,
    Run,
    RunRequest,
    ToolCallRequest,
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

    def permit(self, source: str, tool: str, arguments: Mapping[str, str]) -> PolicyDecision:
        """What answering opencode's ``permission.asked`` comes down to.

        The call arrives in the agent's own words. This side does not translate it:
        bindings are policy, pinned to the run, and a copy held here would decide
        under a version nobody recorded.

        The matrix decides first. Only a call it permits is going to happen, so only
        then is there an outbound payload worth reading — and a credential in it turns
        the permission into a refusal.
        """
        if self.run is None:
            raise RunNotOpen("no run has been opened")
        call = ToolCallRequest(
            run_id=self.run.id,
            subject=self.run.subject,
            source=source,
            tool=tool,
            arguments=dict(arguments),
            attributes=dict(self.settings.attributes or {}),
        )
        decision = self.client.decide_call(call)
        if decision.rule_id == UNREACHABLE:
            return self._journal(call, decision)
        # The policy service journalled its own answer; a second copy would read as a
        # second attempt and charge the budget twice.
        if not decision.permitted:
            return decision
        leak = inspect_payload(_payload(arguments), InterceptionPoint.REQUEST, self.governance)
        if leak.effect is Effect.DENY:
            # This one the policy service never saw, so nobody else will record it. It
            # is the call the matrix just recognised, so it goes down as that
            # capability rather than as an anonymous one.
            return self._journal(
                call,
                msgspec.structs.replace(
                    leak, capability=decision.capability, resource=decision.resource
                ),
            )
        return decision

    def _journal(self, call: ToolCallRequest, decision: PolicyDecision) -> PolicyDecision:
        """Only what the policy service never saw lands here, so nothing is doubled.

        The capability comes back on the decision when the call resolved; when it did
        not, the tool names itself in the resource and that is the honest record.
        """
        try:
            self.audit.enqueue(
                AuditEvent(
                    run_id=call.run_id,
                    subject=call.subject,
                    capability=decision.capability,
                    resource=decision.resource or f"{call.source}/{call.tool}",
                    effect=decision.effect,
                    rule_id=decision.rule_id,
                    weight=decision.weight,
                    policy_hash=decision.policy_hash,
                    point=decision.point,
                )
            )
        except AuditBacklogFull as exc:
            return unreachable(
                f"cannot journal the decision: {exc}", self.governance.denied_message
            )
        return decision

    async def flush_audit(self) -> int:
        return await self.audit.drain()
