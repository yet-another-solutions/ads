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

_current_enforcer: ContextVar[Enforcer | None] = ContextVar("ads_policy_enforcer", default=None)


class Enforcer:
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
        context = SecurityContextHolder.require()
        request = DecisionRequest(
            run_id=self._run.id,
            subject=context.subject,
            capability=capability,
            resource=resource,
            attributes=dict(self._attributes),
        )
        decision = self._client.decide(request)
        journalled_by_policy_service = decision.rule_id != UNREACHABLE
        if journalled_by_policy_service:
            return decision
        try:
            self._audit.enqueue(record(request, decision))
        except AuditBacklogFull as exc:
            return unreachable(f"cannot journal the decision: {exc}", self._denied_message)
        return decision


class EnforcerHolder:
    @staticmethod
    def get() -> Enforcer | None:
        return _current_enforcer.get()

    @staticmethod
    def require() -> Enforcer:
        enforcer = _current_enforcer.get()
        if enforcer is None:
            raise AccessDenied("policy enforcement unavailable")
        return enforcer

    @staticmethod
    def set(enforcer: Enforcer | None) -> Token[Enforcer | None]:
        return _current_enforcer.set(enforcer)

    @staticmethod
    def reset(token: Token[Enforcer | None]) -> None:
        _current_enforcer.reset(token)

    @staticmethod
    @contextmanager
    def bound(enforcer: Enforcer) -> Iterator[Enforcer]:
        token = _current_enforcer.set(enforcer)
        try:
            yield enforcer
        finally:
            _current_enforcer.reset(token)


def require_permission(
    capability: Capability, *, resource: str = "", resource_arg: str | None = None
) -> Callable[[F], F]:
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
            capability, _resource_of_call(wrapped, args, kwargs, resource_arg, resource)
        )
        if not decision.permitted:
            raise AccessDenied(decision.message)
        return wrapped(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _resource_of_call(
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
