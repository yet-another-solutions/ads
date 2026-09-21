from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import msgspec
import structlog
from redis.exceptions import RedisError

from ads_policy.audit import AuditBacklogFull, BufferedAuditSink, record
from ads_policy.blocks import ConversationBlock, ConversationBlocks, InMemoryConversationBlocks
from ads_policy.config import DENIED_MESSAGE, PlacementRules
from ads_policy.contract import (
    UNCHECKED_SOURCE_RULE,
    AuditEvent,
    Capability,
    DecisionRequest,
    Effect,
    Interception,
    InterceptionPoint,
    IsolationLevel,
    Mode,
    Policy,
    PolicyDecision,
    PolicyRequest,
    PromptRequest,
    Run,
    RunContext,
    RunRequest,
    RunState,
    Side,
    SourceChecks,
    Switch,
    ToolCallRequest,
)
from ads_policy.isolation import UnknownPlacement, assign_isolation_level
from ads_policy.pdp import PolicyDecisionPoint, Unbound, resolve
from ads_policy.run import RunStore

logger = structlog.get_logger("ads.policy")

NOTHING_INSPECTED = Interception(
    request=Side(checks=frozenset(), on=Switch.OFF),
    response=Side(checks=frozenset(), on=Switch.OFF),
)


@dataclass(frozen=True, slots=True, eq=False)
class PolicyService:
    pdp: PolicyDecisionPoint
    runs: RunStore
    audit: BufferedAuditSink
    placement: PlacementRules = field(default_factory=PlacementRules)
    blocks: ConversationBlocks = field(default_factory=InMemoryConversationBlocks)
    denied_message: str = DENIED_MESSAGE
    default_weight: int = 1

    async def start(self, request: RunRequest) -> Run:
        level = (
            None
            if request.placement is None
            else assign_isolation_level(
                placement=request.placement,
                runtime_class_name=request.runtime_class_name,
                node_labels=request.node_labels,
                settings=self.placement,
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
            conversation=request.conversation,
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

    async def block_conversation(self, conversation: str, budget: int, by: str) -> None:
        await self.blocks.block(
            ConversationBlock(
                conversation=conversation,
                revoked_at=datetime.now(UTC),
                budget=budget,
                by=by,
            )
        )
        logger.info("conversation blocked", conversation=conversation, budget=budget, by=by)

    async def lift_conversation_block(self, conversation: str) -> None:
        await self.blocks.lift(conversation)
        logger.info("conversation block lifted", conversation=conversation)

    async def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        try:
            run = await self.runs.get(call.run_id)
        except RedisError as exc:
            return self._journal_call(
                call, None, self._refuse("run.store", f"run store unreachable: {exc}")
            )
        if run is None:
            return self._journal_call(
                call, None, self._refuse("run.unknown", f"run {call.run_id} is unknown")
            )
        if run.subject != call.subject:
            return self._journal_call(
                call, run, self._refuse("run.subject", f"run {run.id} belongs to someone else")
            )
        pinned_policy = self.pdp.policy_of(run)
        if pinned_policy is None:
            await self._finish_run_whose_policy_is_gone(run)
            return self._journal_call(
                call, run, self._refuse("policy.missing", "pinned policy is gone")
            )
        if pinned_policy.is_unchecked(call.source):
            return self._journal_call(
                call, run, await self._pass_unchecked(call, run, pinned_policy)
            )
        try:
            capability, resource = resolve(call, pinned_policy)
        except Unbound as exc:
            return self._journal_call(call, run, self._refuse(exc.rule_id, str(exc)))
        decision = await self.decide(
            DecisionRequest(
                run_id=call.run_id,
                subject=call.subject,
                capability=capability,
                resource=resource,
                attributes=dict(call.attributes),
                site=call.site,
                source=call.source,
                tool=call.tool,
            )
        )
        return msgspec.structs.replace(decision, capability=capability, resource=resource)

    async def _pass_unchecked(
        self, call: ToolCallRequest, run: Run, policy: Policy
    ) -> PolicyDecision:
        if run.state is not RunState.RUNNING:
            return self._refuse("run.state", f"run {run.id} is {run.state.value}")
        refusal = await self._refusal_of_block(run)
        if refusal is not None:
            return refusal
        await self._extend_lifetime_from_now(run)
        capability, resource = _bound_or_named(call, policy)
        return PolicyDecision(
            effect=Effect.ALLOW,
            rule_id=UNCHECKED_SOURCE_RULE,
            reason=f"this policy does not check {call.source}",
            policy_hash=run.policy_hash,
            capability=capability,
            resource=resource,
            interception=NOTHING_INSPECTED,
        )

    def _journal_call(
        self, call: ToolCallRequest, run: Run | None, decision: PolicyDecision
    ) -> PolicyDecision:
        try:
            self.audit.enqueue(self._call_event(call, run, decision))
        except AuditBacklogFull as exc:
            refusal = self._refuse("audit.backlog", f"cannot journal the decision: {exc}")
            self.audit.enqueue_refusal(self._call_event(call, run, refusal))
            return refusal
        return decision

    def _call_event(
        self, call: ToolCallRequest, run: Run | None, decision: PolicyDecision
    ) -> AuditEvent:
        return AuditEvent(
            run_id=call.run_id,
            subject=call.subject,
            capability=decision.capability,
            resource=decision.resource or f"{call.source}/{call.tool}",
            effect=decision.effect,
            rule_id=decision.rule_id,
            weight=(
                decision.weight
                if decision.effect is Effect.ALLOW
                else decision.weight or self.default_weight
            ),
            policy_hash=decision.policy_hash,
            point=decision.point,
            conversation=_conversation_of(run),
            source=call.source,
            tool=call.tool,
        )

    async def decide(self, request: DecisionRequest) -> PolicyDecision:
        try:
            run = await self.runs.get(request.run_id)
        except RedisError as exc:
            return self._journal(
                request, None, self._refuse("run.store", f"run store unreachable: {exc}")
            )
        if run is None:
            decision = self._refuse(
                "run.unknown", f"run {request.run_id} is unknown or past its lifetime"
            )
        else:
            decision = await self._decide_in(run, request)
        return self._journal(request, run, decision)

    async def decide_prompt(self, request: PromptRequest) -> PolicyDecision:
        try:
            run = await self.runs.get(request.run_id)
        except RedisError as exc:
            return self._refuse("run.store", f"run store unreachable: {exc}")
        if run is None:
            return self._refuse(
                "run.unknown", f"run {request.run_id} is unknown or past its lifetime"
            )
        if run.subject != request.subject:
            return self._refuse("run.subject", f"run {run.id} belongs to someone else")
        if run.state is not RunState.RUNNING:
            return self._refuse("run.state", f"run {run.id} is {run.state.value}")
        pinned_policy = self.pdp.policy_of(run)
        if pinned_policy is None:
            await self._finish_run_whose_policy_is_gone(run)
            return self._refuse("policy.missing", "pinned policy is gone")
        try:
            blocked = await self.blocks.is_blocked(run.conversation)
        except RedisError as exc:
            return self._refuse("run.store", f"conversation blocks unreachable: {exc}")
        if blocked:
            return self._refuse(
                "conversation.revoked", f"conversation {run.conversation} is blocked"
            )
        await self._extend_lifetime_from_now(run)
        return PolicyDecision(
            effect=Effect.ALLOW,
            rule_id="prompt.inspected",
            reason="the prompt is inspected by the checks this policy states",
            policy_hash=run.policy_hash,
            point=InterceptionPoint.PROMPT,
            interception=pinned_policy.interception,
        )

    async def _decide_in(self, run: Run, request: DecisionRequest) -> PolicyDecision:
        if run.subject != request.subject:
            return self._refuse("run.subject", f"run {run.id} belongs to someone else")
        if run.state is not RunState.RUNNING:
            return self._refuse("run.state", f"run {run.id} is {run.state.value}")
        if self.pdp.policy_of(run) is None:
            await self._finish_run_whose_policy_is_gone(run)
            return self._refuse("policy.missing", "pinned policy is gone")
        refusal = await self._refusal_of_block(run)
        if refusal is not None:
            return refusal
        decision = self._decide_running(run, request)
        await self._extend_lifetime_from_now(run)
        return decision

    async def _refusal_of_block(self, run: Run) -> PolicyDecision | None:
        try:
            blocked = await self.blocks.is_blocked(run.conversation)
        except RedisError as exc:
            return self._refuse("run.store", f"conversation blocks unreachable: {exc}")
        if blocked:
            return self._refuse(
                "conversation.revoked", f"conversation {run.conversation} is blocked"
            )
        return None

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
            settings=self.placement,
        )

    async def _finish_run_whose_policy_is_gone(self, run: Run) -> None:
        if run.state is not RunState.RUNNING:
            return
        try:
            await self.runs.finish(run.id)
        except (KeyError, RedisError) as exc:
            logger.warning("run with a lost policy not finished", run_id=run.id, error=str(exc))
            return
        logger.info("run finished: its policy is gone", run_id=run.id)

    async def _extend_lifetime_from_now(self, run: Run) -> None:
        try:
            await self.runs.touch(run)
        except RedisError as exc:
            logger.warning("run lifetime not extended", run_id=run.id, error=str(exc))

    def _journal(
        self, request: DecisionRequest, run: Run | None, decision: PolicyDecision
    ) -> PolicyDecision:
        conversation = _conversation_of(run)
        try:
            self.audit.enqueue(record(request, decision, conversation=conversation))
        except AuditBacklogFull as exc:
            refusal = self._refuse("audit.backlog", f"cannot journal the decision: {exc}")
            self.audit.enqueue_refusal(record(request, refusal, conversation=conversation))
            return refusal
        return decision

    def version(self) -> dict[str, str]:
        policy = self.pdp.policy
        return {
            "schema_version": policy.schema_version,
            "version": policy.version,
            "hash": self.pdp.policy_hash,
            "mode": policy.mode.value,
        }

    def sources(self) -> tuple[SourceChecks, ...]:
        return self.pdp.policy.source_checks()

    async def flush_audit(self) -> int:
        return await self.audit.drain()

    def _refuse(self, rule_id: str, reason: str) -> PolicyDecision:
        return PolicyDecision(
            effect=Effect.DENY,
            rule_id=rule_id,
            reason=reason,
            message=self.denied_message,
            policy_hash=self.pdp.policy_hash,
            mode=Mode.ENFORCE,
        )


def _bound_or_named(call: ToolCallRequest, policy: Policy) -> tuple[Capability | None, str]:
    try:
        return resolve(call, policy)
    except Unbound:
        return None, f"{call.source}/{call.tool}"


def _conversation_of(run: Run | None) -> str:
    return "" if run is None else run.conversation
