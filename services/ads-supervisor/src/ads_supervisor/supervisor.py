from __future__ import annotations

from collections.abc import Mapping, Sequence
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
    Mode,
    Placement,
    PolicyDecision,
    Run,
    RunRequest,
    Switch,
    ToolCallRequest,
)
from ads_policy.output import inspect_payload, inspect_texts
from ads_supervisor.config import Settings

logger = structlog.get_logger("ads.supervisor")


def _payload(arguments: Mapping[str, str]) -> str:
    """What the call actually sends. Values only: an argument name is never a secret.

    Newline-joined so that two harmless values cannot run together into something that
    looks like one credential.
    """
    return "\n".join(arguments.values())


def _mode(switch: Switch) -> Mode:
    """The switch, said in the vocabulary a PEP already reads a decision with.

    ``permitted`` and ``enforced`` are how every other decision is acted on; a payload
    finding under review is the same thing the matrix already means by review.
    """
    return Mode.ENFORCE if switch is Switch.ENFORCE else Mode.REVIEW


class RunNotOpen(RuntimeError):
    """Asked to decide before a run exists, which nothing is allowed to do."""


@dataclass(frozen=True, slots=True)
class Reading:
    """A tool result read: the verdict, and the texts as the agent should get them."""

    decision: PolicyDecision
    texts: tuple[str, ...]


class Sandbox(msgspec.Struct, frozen=True):
    """Where an agent's task runs, as told by whoever put it there.

    This service stands outside every sandbox, so it cannot see one. The component
    that created the pod can: it chose the runtime class and knows the node it landed
    on. It sends that here, and the policy service derives the isolation level from it.
    Nothing has a default — a guessed placement would decide under the wrong rules.
    """

    project: str
    repo: str
    env: str
    workdir: str
    placement: Placement
    runtime_class_name: str | None = None
    node_labels: dict[str, str] = msgspec.field(default_factory=dict)


@dataclass(slots=True, eq=False)
class Supervisor:
    """The PEP: it asks the PDP about every call and journals what the PDP never saw.

    It sits outside the boundary the agent executes in, so the agent cannot reach it
    to silence it. Nothing here inspects the tool call beyond naming it: the decision
    is the policy service's, and this side only enforces and records.

    One process serves every agent and every run. The run arrives with the call rather
    than being held here, and where it runs arrives with its opening.
    """

    settings: Settings
    client: PolicyClient
    audit: BufferedAuditSink
    governance: GovernanceSettings = field(default_factory=GovernanceSettings)

    def open(self, sandbox: Sandbox) -> Run:
        """Open a run for a task in ``sandbox``. Only the launcher may call this."""
        started = self.client.start_run(
            RunRequest(
                subject=self.settings.subject,
                project=sandbox.project,
                repo=sandbox.repo,
                env=sandbox.env,
                workdir=sandbox.workdir,
                placement=sandbox.placement,
                runtime_class_name=sandbox.runtime_class_name,
                node_labels=dict(sandbox.node_labels),
            )
        )
        logger.info("run opened", run_id=started.id, isolation_level=started.isolation_level.value)
        return started

    def permit(
        self, run_id: str, source: str, tool: str, arguments: Mapping[str, str]
    ) -> PolicyDecision:
        """Decide one tool call, named as the agent names it.

        The call arrives in the agent's own words. This side does not translate it:
        bindings are policy, pinned to the run, and a copy held here would decide
        under a version nobody recorded.

        The matrix decides first. Only a call it permits is going to happen, so only
        then is there an outbound payload worth reading — and a credential in it turns
        the permission into a refusal, unless this side is switched to review.
        """
        if not run_id:
            raise RunNotOpen("the call carries no run")
        call = ToolCallRequest(
            run_id=run_id,
            subject=self.settings.subject,
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
        side = decision.interception.side(InterceptionPoint.REQUEST)
        if side.on is Switch.OFF:
            return decision
        leak = inspect_payload(
            _payload(arguments), InterceptionPoint.REQUEST, self.governance, side.checks
        )
        if leak.effect is Effect.DENY:
            # This one the policy service never saw, so nobody else will record it. It
            # is the call the matrix just recognised, so it goes down as that
            # capability rather than as an anonymous one. Under review the row is the
            # same row; only `mode` differs, and a PEP reads that off `permitted`.
            return self._journal(
                call,
                msgspec.structs.replace(
                    leak,
                    capability=decision.capability,
                    resource=decision.resource,
                    mode=_mode(side.on),
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

    def inspect_result(
        self, run_id: str, decision: PolicyDecision, texts: Sequence[str]
    ) -> Reading:
        """What came back from a tool, one string at a time, as the agent should get it.

        A credential is redacted rather than refused: the result is still useful with
        the secret cut out, and refusing it after the call already happened protects
        nothing. Injected instructions are a warning, never a verdict.

        Switched off, nothing is read at all — on a large result that is the whole
        cost of this side. Switched to review, the finding is recorded and the texts
        go back untouched. Enforced, they go back cleaned even if the finding could not
        be journalled: a lost row must not become a leaked secret.
        """
        given = tuple(texts)
        side = decision.interception.side(InterceptionPoint.RESPONSE)
        if side.on is Switch.OFF:
            unread = PolicyDecision(
                effect=Effect.ALLOW,
                rule_id="payload.unread",
                reason="inbound inspection is off",
                point=InterceptionPoint.RESPONSE,
            )
            return Reading(unread, given)
        found, cleaned = inspect_texts(given, self.governance, side.checks)
        if found.effect is Effect.ALLOW and not found.warnings:
            return Reading(found, given)
        recorded = self._journal(
            ToolCallRequest(run_id=run_id, subject=self.settings.subject, source="", tool=""),
            msgspec.structs.replace(
                found,
                capability=decision.capability,
                resource=decision.resource,
                mode=_mode(side.on),
            ),
        )
        return Reading(recorded, cleaned if side.on is Switch.ENFORCE else given)

    async def flush_audit(self) -> int:
        return await self.audit.drain()
