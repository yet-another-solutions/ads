from __future__ import annotations

import hashlib
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import msgspec
import structlog

from ads_commons.security import AccessTokenVerifier, InvalidAccessToken
from ads_guardrail.config import Settings
from ads_guardrail.contract import Application, Opening, Workspace
from ads_guardrail.scanner import InjectionScan
from ads_policy.audit import AuditBacklogFull, BufferedAuditSink
from ads_policy.client import UNREACHABLE, PolicyClient, unreachable
from ads_policy.config import PayloadInspection
from ads_policy.contract import (
    AuditEvent,
    CheckKind,
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
    string_values,
)
from ads_policy.output import (
    inspect_payload,
    inspect_texts,
    prompt_injection_found,
    prompt_injection_unchecked,
)

logger = structlog.get_logger("ads.guardrail")


def fingerprint(bearer: str) -> str:
    return hashlib.sha256(bearer.encode("utf-8")).hexdigest()


def person_holder_key(subject: str) -> str:
    return f"user:{subject}"


def application_holder_key(key_sha256: str) -> str:
    return f"key:{key_sha256}"


def _newline_joined_argument_values(arguments: Mapping[str, Any]) -> str:
    return "\n".join(string_values(dict(arguments)))


def _as_recorded_under(switch: Switch, decision: PolicyDecision) -> PolicyDecision:
    if switch is Switch.ENFORCE:
        return msgspec.structs.replace(decision, mode=Mode.ENFORCE)
    return msgspec.structs.replace(decision, mode=Mode.REVIEW, weight=0)


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
    withheld: bool = False


@dataclass(slots=True, eq=False)
class Guardrail:
    settings: Settings
    client: PolicyClient
    audit: BufferedAuditSink
    inspection: PayloadInspection = field(default_factory=PayloadInspection)
    person_token_verifier: AccessTokenVerifier | None = None
    _applications_by_fingerprint: dict[str, Application] = field(init=False)
    _application_run_opening: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self._applications_by_fingerprint = {
            application.key_sha256: application for application in self.settings.applications
        }

    def open_run(self, opening: Opening) -> Run:
        return self._start_run(
            self._verified_person(opening.bearer), opening.workspace, opening.conversation
        )

    def finish_run(self, run_id: str) -> Run | None:
        try:
            finished = self.client.finish_run(run_id)
        except ConnectionError as exc:
            raise RunNotOpen(f"runs cannot be reached: {exc}") from exc
        if finished is not None:
            logger.info("run finished", run_id=finished.id, state=finished.state.value)
        return finished

    def find_run(self, run_id: str) -> Run | None:
        try:
            return self.client.run(run_id)
        except ConnectionError as exc:
            raise RunNotOpen(f"runs cannot be looked up: {exc}") from exc

    def get_run(self, run_id: str) -> Run:
        if not run_id:
            raise RunNotOpen("the call carries no run")
        named = self.find_run(run_id)
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
        arguments: Mapping[str, Any],
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
            return self._journal_own_decision(run, call, decision)
        if not decision.permitted:
            return decision
        outbound = decision.interception.side(InterceptionPoint.REQUEST)
        if outbound.on is Switch.OFF:
            return decision
        leak = inspect_payload(
            _newline_joined_argument_values(arguments),
            InterceptionPoint.REQUEST,
            self.inspection,
            outbound.checks,
        )
        if leak.effect is not Effect.DENY:
            return decision
        return self._journal_own_decision(
            run,
            call,
            _as_recorded_under(
                outbound.switch_for(CheckKind.SECRETS),
                msgspec.structs.replace(
                    leak, capability=decision.capability, resource=decision.resource
                ),
            ),
        )

    def inspect_tool_result(
        self,
        run: Run,
        decision: PolicyDecision,
        texts: Sequence[str],
        injection_scan: InjectionScan | None = None,
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
        injection_switch = inbound.switch_for(CheckKind.INJECTION)
        if injection_switch is not Switch.OFF:
            injection = self._injection_verdict(injection_scan)
            if injection is not None:
                recorded = self._journal_result_decision(run, decision, injection_switch, injection)
                if not recorded.permitted:
                    return Reading(recorded, (), withheld=True)
        secrets_switch = inbound.switch_for(CheckKind.SECRETS)
        found, redacted = inspect_texts(given, self.inspection, inbound.checks)
        if found.effect is Effect.ALLOW:
            return Reading(found, given)
        recorded = self._journal_result_decision(run, decision, secrets_switch, found)
        return Reading(recorded, redacted if secrets_switch is Switch.ENFORCE else given)

    def inspect_prompt(
        self,
        run: Run,
        decision: PolicyDecision,
        texts: Sequence[str],
        injection_scan: InjectionScan | None = None,
    ) -> Reading:
        given = tuple(texts)
        side = decision.interception.side(InterceptionPoint.PROMPT)
        if side.on is Switch.OFF:
            unread = PolicyDecision(
                effect=Effect.ALLOW,
                rule_id="prompt.unread",
                reason="prompts are not inspected",
                point=InterceptionPoint.PROMPT,
            )
            return Reading(unread, given)
        injection_switch = side.switch_for(CheckKind.INJECTION)
        if injection_switch is not Switch.OFF:
            injection = self._injection_verdict(injection_scan)
            if injection is not None:
                recorded = self._journal_prompt_decision(run, injection_switch, injection)
                if not recorded.permitted:
                    return Reading(recorded, (), withheld=True)
        secrets_switch = side.switch_for(CheckKind.SECRETS)
        found, redacted = inspect_texts(given, self.inspection, side.checks)
        if found.effect is Effect.ALLOW:
            return Reading(found, given)
        recorded = self._journal_prompt_decision(run, secrets_switch, found)
        return Reading(recorded, redacted if secrets_switch is Switch.ENFORCE else given)

    def _journal_prompt_decision(
        self, run: Run, switch: Switch, found: PolicyDecision
    ) -> PolicyDecision:
        return self._journal_own_decision(
            run,
            ToolCallRequest(run_id=run.id, subject=run.subject, source="", tool=""),
            _as_recorded_under(
                switch,
                msgspec.structs.replace(
                    found,
                    point=InterceptionPoint.PROMPT,
                    resource=run.conversation,
                ),
            ),
        )

    def _injection_verdict(self, injection_scan: InjectionScan | None) -> PolicyDecision | None:
        if injection_scan is None:
            return prompt_injection_unchecked("the result was not scanned", self.inspection)
        if injection_scan.unavailable_reason:
            return prompt_injection_unchecked(injection_scan.unavailable_reason, self.inspection)
        if injection_scan.found:
            return prompt_injection_found(injection_scan.highest_score, self.inspection)
        return None

    def _journal_result_decision(
        self, run: Run, call_decision: PolicyDecision, switch: Switch, found: PolicyDecision
    ) -> PolicyDecision:
        return self._journal_own_decision(
            run,
            ToolCallRequest(run_id=run.id, subject=run.subject, source="", tool=""),
            _as_recorded_under(
                switch,
                msgspec.structs.replace(
                    found, capability=call_decision.capability, resource=call_decision.resource
                ),
            ),
        )

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

    def _start_run(self, holder: Holder, workspace: Workspace, conversation: str = "") -> Run:
        started = self.client.start_run(
            RunRequest(
                subject=holder.subject,
                project=workspace.project,
                repo=workspace.repo,
                env=workspace.env,
                workdir=workspace.workdir,
                placement=None,
                holder=holder.key,
                conversation=conversation,
            )
        )
        logger.info(
            "run opened",
            run_id=started.id,
            subject=started.subject,
            holder=started.holder,
            conversation=started.conversation,
        )
        return started

    def _journal_own_decision(
        self, run: Run, call: ToolCallRequest, decision: PolicyDecision
    ) -> PolicyDecision:
        try:
            self.audit.enqueue(self._own_event(run, call, decision))
        except AuditBacklogFull as exc:
            refusal = unreachable(
                f"cannot journal the decision: {exc}", self.inspection.denied_message
            )
            self.audit.enqueue_refusal(self._own_event(run, call, refusal))
            return refusal
        return decision

    def _own_event(self, run: Run, call: ToolCallRequest, decision: PolicyDecision) -> AuditEvent:
        return AuditEvent(
            run_id=run.id,
            subject=run.subject,
            capability=decision.capability,
            resource=decision.resource or f"{call.source}/{call.tool}",
            effect=decision.effect,
            rule_id=decision.rule_id,
            weight=decision.weight,
            policy_hash=decision.policy_hash,
            point=decision.point,
            conversation=run.conversation,
        )
