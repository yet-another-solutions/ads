from __future__ import annotations

import hashlib
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import msgspec
import structlog

from ads_commons.security import AccessTokenVerifier, InvalidAccessToken
from ads_guardrail.config import Settings
from ads_guardrail.contract import Application, Opening, Workspace
from ads_policy.audit import AuditBacklogFull, BufferedAuditSink
from ads_policy.client import UNREACHABLE, PolicyClient, unreachable
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    AuditEvent,
    Effect,
    InterceptionPoint,
    Mode,
    PolicyDecision,
    Run,
    RunRequest,
    RunState,
    Site,
    Switch,
    ToolCallRequest,
)
from ads_policy.output import inspect_payload, inspect_texts

logger = structlog.get_logger("ads.guardrail")


def fingerprint(bearer: str) -> str:
    return hashlib.sha256(bearer.encode("utf-8")).hexdigest()


def person_holder_key(subject: str) -> str:
    return f"user:{subject}"


def application_holder_key(key_sha256: str) -> str:
    return f"key:{key_sha256}"


def _newline_joined_argument_values(arguments: Mapping[str, str]) -> str:
    return "\n".join(arguments.values())


def _decision_mode_for(switch: Switch) -> Mode:
    return Mode.ENFORCE if switch is Switch.ENFORCE else Mode.REVIEW


class RunNotOpen(RuntimeError):
    pass


class NotAPerson(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Holder:
    key: str
    subject: str
    application: Application | None = None


@dataclass(frozen=True, slots=True)
class Reading:
    decision: PolicyDecision
    texts: tuple[str, ...]


@dataclass(slots=True, eq=False)
class Guardrail:
    settings: Settings
    client: PolicyClient
    audit: BufferedAuditSink
    governance: GovernanceSettings = field(default_factory=GovernanceSettings)
    person_token_verifier: AccessTokenVerifier | None = None
    _applications_by_fingerprint: dict[str, Application] = field(init=False)
    _application_run_opening: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self._applications_by_fingerprint = {
            application.key_sha256: application for application in self.settings.applications
        }

    def open_run(self, opening: Opening) -> Run:
        return self._start_run(self._verified_person(opening.bearer), opening.workspace)

    def finish_run(self, run_id: str) -> Run | None:
        try:
            finished = self.client.finish_run(run_id)
        except ConnectionError as exc:
            raise RunNotOpen(f"runs cannot be reached: {exc}") from exc
        if finished is not None:
            logger.info("run finished", run_id=finished.id, state=finished.state.value)
        return finished

    def get_run(self, run_id: str) -> Run:
        if not run_id:
            raise RunNotOpen("the call carries no run")
        try:
            named = self.client.run(run_id)
        except ConnectionError as exc:
            raise RunNotOpen(f"runs cannot be looked up: {exc}") from exc
        if named is None:
            raise RunNotOpen("the call names a run nobody opened")
        return named

    def find_run_of_caller(self, bearer: str, named_run_id: str = "") -> Run:
        try:
            holder = self._holder_of(bearer)
        except NotAPerson as exc:
            raise RunNotOpen(str(exc)) from exc
        try:
            if named_run_id:
                return self._named_run_of(holder, named_run_id)
            if holder.application is not None:
                return self._current_application_run(holder, holder.application)
            held = self.client.runs_held(holder.key)
        except ConnectionError as exc:
            raise RunNotOpen(f"runs cannot be looked up: {exc}") from exc
        running = [run for run in held if run.state is RunState.RUNNING]
        if len(running) > 1:
            raise RunNotOpen("several runs are open for this caller; name one")
        if running:
            return running[0]
        if held:
            return held[0]
        raise RunNotOpen("no run is open for this caller")

    def decide_tool_call(
        self,
        run: Run,
        source: str,
        tool: str,
        arguments: Mapping[str, str],
        site: Site | None = None,
    ) -> PolicyDecision:
        call = ToolCallRequest(
            run_id=run.id,
            subject=run.subject,
            source=source,
            tool=tool,
            arguments=dict(arguments),
            attributes=dict(self.settings.attributes or {}),
            site=site,
        )
        decision = self.client.decide_call(call)
        if decision.rule_id == UNREACHABLE:
            return self._journal_own_decision(call, decision)
        if not decision.permitted:
            return decision
        outbound = decision.interception.side(InterceptionPoint.REQUEST)
        if outbound.on is Switch.OFF:
            return decision
        leak = inspect_payload(
            _newline_joined_argument_values(arguments),
            InterceptionPoint.REQUEST,
            self.governance,
            outbound.checks,
        )
        if leak.effect is not Effect.DENY:
            return decision
        return self._journal_own_decision(
            call,
            msgspec.structs.replace(
                leak,
                capability=decision.capability,
                resource=decision.resource,
                mode=_decision_mode_for(outbound.on),
            ),
        )

    def inspect_tool_result(
        self, run: Run, decision: PolicyDecision, texts: Sequence[str]
    ) -> Reading:
        given = tuple(texts)
        inbound = decision.interception.side(InterceptionPoint.RESPONSE)
        if inbound.on is Switch.OFF:
            unread = PolicyDecision(
                effect=Effect.ALLOW,
                rule_id="payload.unread",
                reason="inbound inspection is off",
                point=InterceptionPoint.RESPONSE,
            )
            return Reading(unread, given)
        found, redacted = inspect_texts(given, self.governance, inbound.checks)
        if found.effect is Effect.ALLOW and not found.warnings:
            return Reading(found, given)
        recorded = self._journal_own_decision(
            ToolCallRequest(run_id=run.id, subject=run.subject, source="", tool=""),
            msgspec.structs.replace(
                found,
                capability=decision.capability,
                resource=decision.resource,
                mode=_decision_mode_for(inbound.on),
            ),
        )
        return Reading(recorded, redacted if inbound.on is Switch.ENFORCE else given)

    async def flush_audit(self) -> int:
        return await self.audit.drain()

    def _holder_of(self, bearer: str) -> Holder:
        if not bearer:
            raise NotAPerson("the call carries no credentials")
        application = self._applications_by_fingerprint.get(fingerprint(bearer))
        if application is not None:
            return Holder(
                application_holder_key(application.key_sha256), application.name, application
            )
        return self._verified_person(bearer)

    def _verified_person(self, bearer: str) -> Holder:
        audience = self.settings.person_token_audience
        if self.person_token_verifier is None or not audience:
            raise NotAPerson("no audience is configured for people's tokens")
        try:
            context = self.person_token_verifier.authenticate(bearer, audience=audience)
        except InvalidAccessToken as exc:
            raise NotAPerson(f"the token does not verify: {exc.detail}") from exc
        return Holder(person_holder_key(context.subject), context.subject)

    def _named_run_of(self, holder: Holder, run_id: str) -> Run:
        named = self.client.run(run_id)
        if named is None or named.holder != holder.key:
            raise RunNotOpen("the call names a run that is not its own")
        return named

    def _current_application_run(self, holder: Holder, application: Application) -> Run:
        with self._application_run_opening:
            held = self.client.runs_held(holder.key)
            running = sorted(
                (run for run in held if run.state is RunState.RUNNING), key=lambda run: run.id
            )
            if running:
                return running[0]
            revoked_stays_revoked = [run for run in held if run.state is RunState.REVOKED]
            if revoked_stays_revoked:
                return revoked_stays_revoked[0]
            return self._start_run(holder, application.workspace)

    def _start_run(self, holder: Holder, workspace: Workspace) -> Run:
        started = self.client.start_run(
            RunRequest(
                subject=holder.subject,
                project=workspace.project,
                repo=workspace.repo,
                env=workspace.env,
                workdir=workspace.workdir,
                placement=None,
                holder=holder.key,
            )
        )
        logger.info("run opened", run_id=started.id, subject=started.subject, holder=started.holder)
        return started

    def _journal_own_decision(
        self, call: ToolCallRequest, decision: PolicyDecision
    ) -> PolicyDecision:
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
