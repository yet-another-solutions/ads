from __future__ import annotations

from dataclasses import dataclass, field

import msgspec
import structlog
from redis.exceptions import RedisError

from ads_policy.audit import AuditBacklogFull, BufferedAuditSink, record
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    AuditEvent,
    DecisionRequest,
    Effect,
    IsolationLevel,
    Mode,
    PolicyDecision,
    PolicyRequest,
    Run,
    RunContext,
    RunRequest,
    RunState,
    ToolCallRequest,
)
from ads_policy.isolation import UnknownPlacement, assign_isolation_level
from ads_policy.pdp import PolicyDecisionPoint, Unbound, resolve
from ads_policy.run import RunStore

logger = structlog.get_logger("ads.policy")


@dataclass(frozen=True, slots=True, eq=False)
class PolicyService:
    pdp: PolicyDecisionPoint
    runs: RunStore
    audit: BufferedAuditSink
    settings: GovernanceSettings = field(default_factory=GovernanceSettings)

    async def start(self, request: RunRequest) -> Run:
        level = (
            None
            if request.placement is None
            else assign_isolation_level(
                placement=request.placement,
                runtime_class_name=request.runtime_class_name,
                node_labels=request.node_labels,
                settings=self.settings,
            )
        )
        return await self.runs.start(
            subject=request.subject,
            context=RunContext(
                project=request.project,
                repo=request.repo,
                env=request.env,
                workdir=request.workdir,
            ),
            isolation_level=level,
            policy_hash=self.pdp.policy_hash,
            holder=request.holder,
        )

    async def run(self, run_id: str) -> Run | None:
        return await self.runs.get(run_id)

    async def held_by(self, holder: str) -> list[Run]:
        return await self.runs.held_by(holder)

    async def revoke(self, run_id: str) -> Run | None:
        try:
            return await self.runs.revoke(run_id)
        except KeyError:
            return None

    async def finish(self, run_id: str) -> Run | None:
        run = await self.runs.get(run_id)
        if run is None:
            return None
        already_finished_or_revoked = run.state is not RunState.RUNNING
        if already_finished_or_revoked:
            return run
        return await self.runs.finish(run_id)

    async def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        try:
            run = await self.runs.get(call.run_id)
        except RedisError as exc:
            return self._journal_unresolved_call(
                call, self._refuse("run.store", f"run store unreachable: {exc}")
            )
        if run is None:
            return self._journal_unresolved_call(
                call, self._refuse("run.unknown", f"run {call.run_id} is unknown")
            )
        if run.subject != call.subject:
            return self._journal_unresolved_call(
                call, self._refuse("run.subject", f"run {run.id} belongs to someone else")
            )
        pinned_policy = self.pdp.policy_of(run)
        if pinned_policy is None:
            return self._journal_unresolved_call(
                call, self._refuse("policy.missing", "pinned policy is gone")
            )
        try:
            capability, resource = resolve(call, pinned_policy)
        except Unbound as exc:
            return self._journal_unresolved_call(call, self._refuse(exc.rule_id, str(exc)))
        decision = await self.decide(
            DecisionRequest(
                run_id=call.run_id,
                subject=call.subject,
                capability=capability,
                resource=resource,
                attributes=dict(call.attributes),
                site=call.site,
            )
        )
        return msgspec.structs.replace(decision, capability=capability, resource=resource)

    def _journal_unresolved_call(
        self, call: ToolCallRequest, decision: PolicyDecision
    ) -> PolicyDecision:
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
        elif run.state is not RunState.RUNNING:
            decision = self._refuse("run.state", f"run {run.id} is {run.state.value}")
        else:
            decision = self._decide_running(run, request)
            await self._extend_lifetime_from_now(run)
        return self._journal(request, decision)

    def _decide_running(self, run: Run, request: DecisionRequest) -> PolicyDecision:
        try:
            level = self._level_of_call(run, request)
        except UnknownPlacement as exc:
            return self._refuse("site.unknown", f"the call's site is not confirmed: {exc}")
        if level is None:
            return self._refuse(
                "site.missing", f"run {run.id} has no level and the call names no site"
            )
        return self.pdp.decide_for_run(
            run,
            PolicyRequest(
                subject=run.subject,
                capability=request.capability,
                resource=request.resource,
                isolation_level=level,
                context=run.context,
                attributes=dict(request.attributes),
            ),
        )

    def _level_of_call(self, run: Run, request: DecisionRequest) -> IsolationLevel | None:
        site = request.site
        if site is None:
            return run.isolation_level
        return assign_isolation_level(
            placement=site.placement,
            runtime_class_name=site.runtime_class_name,
            node_labels=site.node_labels,
            settings=self.settings,
        )

    async def _extend_lifetime_from_now(self, run: Run) -> None:
        try:
            await self.runs.touch(run)
        except RedisError as exc:
            logger.warning("run lifetime not extended", run_id=run.id, error=str(exc))

    def _journal(self, request: DecisionRequest, decision: PolicyDecision) -> PolicyDecision:
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
