from __future__ import annotations

import inspect
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, TypeVar

import wrapt

from ads.security_holder import SecurityContextHolder
from ads_commons.security import AccessDenied
from ads_policy.audit import AuditBacklogFull, BufferedAuditSink, record
from ads_policy.client import UNREACHABLE, PolicyClient, unreachable
from ads_policy.config import GovernanceSettings
from ads_policy.contract import Capability, DecisionRequest, PolicyDecision, Run

F = TypeVar("F", bound=Callable[..., Any])

_current: ContextVar[Enforcer | None] = ContextVar("ads_policy_enforcer", default=None)


class Enforcer:
    """Asks the PDP on behalf of the current run, and records what the PDP could not.

    The journal belongs to the policy service, which sees both the question and its
    own verdict. Only a decision made here instead of it — because it was out of
    reach — would otherwise leave no trace, so only that one is published.
    """

    def __init__(
        self,
        *,
        client: PolicyClient,
        run: Run,
        audit: BufferedAuditSink,
        attributes: Mapping[str, str] | None = None,
        denied_message: str | None = None,
    ) -> None:
        self._client = client
        self._run = run
        self._audit = audit
        self._attributes = dict(attributes or {})
        self._denied_message = denied_message or GovernanceSettings().denied_message

    def check(self, capability: Capability, resource: str) -> PolicyDecision:
        """The level and the context live in the run, so a caller cannot declare its own."""
        context = SecurityContextHolder.require()
        request = DecisionRequest(
            run_id=self._run.id,
            subject=context.subject,
            capability=capability,
            resource=resource,
            attributes=dict(self._attributes),
        )
        decision = self._client.decide(request)
        if decision.rule_id != UNREACHABLE:
            # The policy service journalled its own answer; recording it again would
            # read as a second attempt and charge the budget twice.
            return decision
        try:
            self._audit.enqueue(record(request, decision))
        except AuditBacklogFull as exc:
            return unreachable(f"cannot journal the decision: {exc}", self._denied_message)
        return decision


class EnforcerHolder:
    """Current Enforcer for this HTTP request or detached work."""

    @staticmethod
    def get() -> Enforcer | None:
        return _current.get()

    @staticmethod
    def require() -> Enforcer:
        enforcer = _current.get()
        if enforcer is None:
            raise AccessDenied("policy enforcement unavailable")
        return enforcer

    @staticmethod
    def set(enforcer: Enforcer | None) -> Token[Enforcer | None]:
        return _current.set(enforcer)

    @staticmethod
    def reset(token: Token[Enforcer | None]) -> None:
        _current.reset(token)

    @staticmethod
    @contextmanager
    def bound(enforcer: Enforcer) -> Iterator[Enforcer]:
        token = _current.set(enforcer)
        try:
            yield enforcer
        finally:
            _current.reset(token)


def require_permission(
    capability: Capability, *, resource: str = "", resource_arg: str | None = None
) -> Callable[[F], F]:
    """wrapt advice: the PDP must permit ``capability`` on the resource in hand."""

    @wrapt.decorator
    def wrapper(
        wrapped: Callable[..., Any],
        instance: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        del instance
        SecurityContextHolder.require()
        enforcer = EnforcerHolder.require()
        decision = enforcer.check(
            capability, _resource(wrapped, args, kwargs, resource_arg, resource)
        )
        if not decision.permitted:
            raise AccessDenied(decision.message)
        return wrapped(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _resource(
    wrapped: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    resource_arg: str | None,
    default: str,
) -> str:
    if resource_arg is None:
        return default
    bound = inspect.signature(wrapped).bind(*args, **kwargs)
    bound.apply_defaults()
    return str(bound.arguments.get(resource_arg, default))
