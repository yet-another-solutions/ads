from __future__ import annotations

import hashlib
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import msgspec
import structlog

from ads_commons.security import AccessTokenVerifier, InvalidAccessToken
from ads_guardrail.config import Settings
from ads_guardrail.contract import Application, Opening, Sandbox
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
    Switch,
    ToolCallRequest,
)
from ads_policy.output import inspect_payload, inspect_texts

logger = structlog.get_logger("ads.guardrail")

__all__ = [
    "Guardrail",
    "Holder",
    "NotAPerson",
    "Opening",
    "Reading",
    "RunNotOpen",
    "Sandbox",
    "application_key",
    "fingerprint",
    "person",
]


def fingerprint(bearer: str) -> str:
    """What is kept of credentials: enough to recognise them, never enough to use them."""
    return hashlib.sha256(bearer.encode("utf-8")).hexdigest()


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
    """A call that belongs to no run this service can act in. It is refused."""


class NotAPerson(ValueError):
    """Credentials offered for a person's run that do not verify as a person's."""


@dataclass(frozen=True, slots=True)
class Holder:
    """Who a call comes from, as runs are kept: never the credential itself.

    A person is their verified ``sub``, so a refreshed token still reaches their run.
    An application is its key's fingerprint, because its key is all it has.
    """

    key: str
    subject: str
    application: Application | None = None


def person(subject: str) -> str:
    return f"user:{subject}"


def application_key(key_sha256: str) -> str:
    return f"key:{key_sha256}"


@dataclass(frozen=True, slots=True)
class Reading:
    """A tool result read: the verdict, and the texts as the agent should get them."""

    decision: PolicyDecision
    texts: tuple[str, ...]


@dataclass(slots=True, eq=False)
class Guardrail:
    """The PEP: it asks the PDP about every call and journals what the PDP never saw.

    It sits outside the boundary the agent executes in, so the agent cannot reach it
    to silence it. Nothing here inspects the tool call beyond naming it: the decision
    is the policy service's, and this side only enforces and records.

    One process serves every agent and every run, and keeps none of them: which run a
    call belongs to, and on whose behalf, is looked up where the run was opened.
    """

    settings: Settings
    client: PolicyClient
    audit: BufferedAuditSink
    governance: GovernanceSettings = field(default_factory=GovernanceSettings)
    #: Checks a person's token. Without one, no person's token is accepted.
    verifier: AccessTokenVerifier | None = None
    _applications: dict[str, Application] = field(init=False)
    #: Calls run on worker threads, and an application's first few arrive together.
    #: Without this each would find no run and open its own.
    _opening: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self._applications = {app.key_sha256: app for app in self.settings.applications}

    def open(self, opening: Opening) -> Run:
        """Open a run for a person. Only whoever created the sandbox may call this.

        An application's run is not opened this way: it is opened here, on its calls.
        """
        holder = self._person(opening.bearer)
        return self._start(holder, opening.sandbox)

    def finish(self, run_id: str) -> Run | None:
        """The task is over. Its holder stops finding it; a later task opens anew."""
        try:
            finished = self.client.finish_run(run_id)
        except ConnectionError as exc:
            raise RunNotOpen(f"runs cannot be reached: {exc}") from exc
        if finished is not None:
            logger.info("run finished", run_id=finished.id, state=finished.state.value)
        return finished

    def find(self, bearer: str, run_id: str = "") -> Run:
        """The run a proxied call belongs to, from who the call comes from.

        A running run of theirs is the run. Several — a person with two sandboxes — and
        the call has to name one, which must still be theirs: a run id alone is not a
        credential. None running, but one revoked or finished, and that is the run:
        the policy service refuses it, and journals the attempt, which a refusal here
        would not do. Nothing at all, and the call belongs to nothing.

        An application's calls never name a run: it has one at a time, opened here.
        """
        try:
            holder = self._holder(bearer)
        except NotAPerson as exc:
            raise RunNotOpen(str(exc)) from exc
        try:
            if run_id:
                named = self.client.run(run_id)
                if named is None or named.holder != holder.key:
                    raise RunNotOpen("the call names a run that is not its own")
                return named
            if holder.application is not None:
                return self._application_run(holder)
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

    def _holder(self, bearer: str) -> Holder:
        """An application by its key, and otherwise a person by their verified token."""
        if not bearer:
            raise NotAPerson("the call carries no credentials")
        mark = fingerprint(bearer)
        application = self._applications.get(mark)
        if application is not None:
            return Holder(application_key(mark), application.name, application)
        return self._person(bearer)

    def _person(self, bearer: str) -> Holder:
        """A person, from a token that verifies: signature, issuer, audience, expiry.

        Nothing in an unverified token can be believed — anyone can write one naming
        anybody. So without a verifier and an audience no person is recognised at all.
        """
        if self.verifier is None or not self.settings.mcp_audience:
            raise NotAPerson("no audience is configured for people's tokens")
        try:
            context = self.verifier.authenticate(bearer, audience=self.settings.mcp_audience)
        except InvalidAccessToken as exc:
            raise NotAPerson(f"the token does not verify: {exc.detail}") from exc
        return Holder(person(context.subject), context.subject)

    def _application_run(self, holder: Holder) -> Run:
        """The application's current run, opened if it has none.

        A revoked run is kept, not replaced: reopening it would make revoking an
        application mean nothing. It stays refused until its lifetime ends, or until
        the application is taken out of the configuration.

        Two replicas can still open one each at the same moment. Both runs are the same
        application in the same place, so either will do; the first by id is taken.
        """
        application = holder.application
        assert application is not None
        with self._opening:
            held = self.client.runs_held(holder.key)
            running = sorted(
                (run for run in held if run.state is RunState.RUNNING), key=lambda run: run.id
            )
            if running:
                return running[0]
            revoked = [run for run in held if run.state is RunState.REVOKED]
            if revoked:
                return revoked[0]
            return self._start(holder, application.sandbox)

    def _start(self, holder: Holder, sandbox: Sandbox) -> Run:
        started = self.client.start_run(
            RunRequest(
                subject=holder.subject,
                project=sandbox.project,
                repo=sandbox.repo,
                env=sandbox.env,
                workdir=sandbox.workdir,
                placement=sandbox.placement,
                runtime_class_name=sandbox.runtime_class_name,
                node_labels=dict(sandbox.node_labels),
                holder=holder.key,
            )
        )
        logger.info(
            "run opened",
            run_id=started.id,
            subject=started.subject,
            holder=started.holder,
            isolation_level=started.isolation_level.value,
        )
        return started

    def run(self, run_id: str) -> Run:
        """A run named by a caller that already proved itself with the API token."""
        if not run_id:
            raise RunNotOpen("the call carries no run")
        try:
            named = self.client.run(run_id)
        except ConnectionError as exc:
            raise RunNotOpen(f"runs cannot be looked up: {exc}") from exc
        if named is None:
            raise RunNotOpen("the call names a run nobody opened")
        return named

    def permit(
        self, run: Run, source: str, tool: str, arguments: Mapping[str, str]
    ) -> PolicyDecision:
        """Decide one tool call, named as the agent names it.

        The call arrives in the agent's own words. This side does not translate it:
        bindings are policy, pinned to the run, and a copy held here would decide
        under a version nobody recorded.

        The matrix decides first. Only a call it permits is going to happen, so only
        then is there an outbound payload worth reading — and a credential in it turns
        the permission into a refusal, unless this side is switched to review.
        """
        call = ToolCallRequest(
            run_id=run.id,
            subject=run.subject,
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

    def inspect_result(self, run: Run, decision: PolicyDecision, texts: Sequence[str]) -> Reading:
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
            ToolCallRequest(run_id=run.id, subject=run.subject, source="", tool=""),
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
