from __future__ import annotations

from collections.abc import Iterable

from ads_policy.contract import AuditEvent, Capability, Effect

DEFAULT_REPEAT_MULTIPLIER = 3


def deny_budget(events: Iterable[AuditEvent], repeat_multiplier: int | None = None) -> int:
    multiplier = DEFAULT_REPEAT_MULTIPLIER if repeat_multiplier is None else repeat_multiplier
    total = 0
    denied_before: set[tuple[Capability | None, str]] = set()
    for event in events:
        if event.effect is not Effect.DENY:
            continue
        denied_call = (event.capability, event.resource)
        total += event.weight * (multiplier if denied_call in denied_before else 1)
        denied_before.add(denied_call)
    return total
