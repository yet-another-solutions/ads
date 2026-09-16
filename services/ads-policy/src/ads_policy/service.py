from __future__ import annotations

from dataclasses import dataclass, field

import msgspec
from redis.exceptions import RedisError

from ads_policy.audit import AuditBacklogFull, BufferedAuditSink, record
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    AuditEvent,
    DecisionRequest,
    Effect,
    Mode,
    PolicyDecision,
    PolicyRequest,
    Run,
    RunContext,
    RunRequest,
    ToolCallRequest,
)
from ads_policy.isolation import assign_isolation_level
from ads_policy.pdp import PolicyDecisionPoint, Unbound, resolve
from ads_policy.run import RunStore


@dataclass(frozen=True, slots=True, eq=False)
class PolicyService:
    """What the API exposes: runs, decisions and the version they were made under."""

    pdp: PolicyDecisionPoint
    runs: RunStore
    audit: BufferedAuditSink
    settings: GovernanceSettings = field(default_factory=GovernanceSettings)

    async def start(self, request: RunRequest) -> Run:
        """The level follows from where the caller scheduled the run, not from a claim."""
        return await self.runs.start(
            subject=request.subject,
            context=RunContext(
                project=request.project,
                repo=request.repo,
                env=request.env,
                workdir=request.workdir,
            ),
            isolation_level=assign_isolation_level(
                placement=request.placement,
                runtime_class_name=request.runtime_class_name,
                node_labels=request.node_labels,
                settings=self.settings,
            ),
            policy_hash=self.pdp.policy_hash,
        )

    async def revoke(self, run_id: str) -> Run | None:
        try:
            return await self.runs.revoke(run_id)
        except KeyError:
            return None

    async def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        """Recognise an agent's tool call, then decide it like any other.

        Resolution happens against the version the run is pinned to, so a binding
        added after the run started does not change what that run may do.
        """
        try:
            run = await self.runs.get(call.run_id)
        except RedisError as exc:
            return self._journal_call(
                call, self._refuse("run.store", f"run store unreachable: {exc}")
            )
        if run is None:
            return self._journal_call(
                call, self._refuse("run.unknown", f"run {call.run_id} is unknown")
            )
        if run.subject != call.subject:
            return self._journal_call(
                call, self._refuse("run.subject", f"run {run.id} belongs to someone else")
            )
        policy = self.pdp.policy_of(run)
        if policy is None:
            return self._journal_call(call, self._refuse("policy.missing", "pinned policy is gone"))
        try:
            capability, resource = resolve(call, policy)
        except Unbound as exc:
            return self._journal_call(call, self._refuse(exc.rule_id, str(exc)))
        decision = await self.decide(
            DecisionRequest(
                run_id=call.run_id,
                subject=call.subject,
                capability=capability,
                resource=resource,
                attributes=dict(call.attributes),
            )
        )
        # The caller asked by tool name, so tell it what that turned out to be.
        return msgspec.structs.replace(decision, capability=capability, resource=resource)

    def _journal_call(self, call: ToolCallRequest, decision: PolicyDecision) -> PolicyDecision:
        """A call nobody could recognise still happened, so it still gets a row.

        No capability, because it never resolved to one. The tool is named in the
        resource instead, which is what a reviewer needs to see: repeated attempts at
        tools nothing binds are probing, and the budget should feel them.
        """
        try:
            self.audit.enqueue(
                AuditEvent(
                    run_id=call.run_id,
                    subject=call.subject,
                    capability=None,
                    resource=f"{call.source}/{call.tool}",
                    effect=decision.effect,
                    rule_id=decision.rule_id,
                    weight=decision.weight or self.settings.default_weight,
                    policy_hash=decision.policy_hash,
                    point=decision.point,
                )
            )
        except AuditBacklogFull as exc:
            return self._refuse("audit.backlog", f"cannot journal the decision: {exc}")
        return decision

    async def decide(self, request: DecisionRequest) -> PolicyDecision:
        try:
            run = await self.runs.get(request.run_id)
        except RedisError as exc:
            return self._journal(
                request, self._refuse("run.store", f"run store unreachable: {exc}")
            )
        if run is None:
            decision = self._refuse(
                "run.unknown", f"run {request.run_id} is unknown or past its lifetime"
            )
        elif run.subject != request.subject:
            decision = self._refuse("run.subject", f"run {run.id} belongs to someone else")
        else:
            decision = self.pdp.decide_for_run(
                run,
                PolicyRequest(
                    subject=run.subject,
                    capability=request.capability,
                    resource=request.resource,
                    isolation_level=run.isolation_level,
                    context=run.context,
                    attributes=dict(request.attributes),
                ),
            )
        return self._journal(request, decision)

    def _journal(self, request: DecisionRequest, decision: PolicyDecision) -> PolicyDecision:
        """A decision nobody can record is a decision nobody may act on."""
        try:
            self.audit.enqueue(record(request, decision))
        except AuditBacklogFull as exc:
            return self._refuse("audit.backlog", f"cannot journal the decision: {exc}")
        return decision

    def version(self) -> dict[str, str]:
        policy = self.pdp.policy
        return {
            "schema_version": policy.schema_version,
            "version": policy.version,
            "hash": self.pdp.policy_hash,
            "mode": policy.mode.value,
        }

    async def flush_audit(self) -> int:
        return await self.audit.drain()

    def _refuse(self, rule_id: str, reason: str) -> PolicyDecision:
        return PolicyDecision(
            effect=Effect.DENY,
            rule_id=rule_id,
            reason=reason,
            message=self.settings.denied_message,
            policy_hash=self.pdp.policy_hash,
            mode=Mode.ENFORCE,
        )
