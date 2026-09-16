from __future__ import annotations

from collections.abc import Iterable

from ads_policy.contract import AuditEvent, Capability, Effect

DEFAULT_REPEAT_MULTIPLIER = 3


def deny_budget(events: Iterable[AuditEvent], repeat_multiplier: int | None = None) -> int:
    """Derived from the journal, never stored: retrying a denied call costs a multiple."""
    multiplier = DEFAULT_REPEAT_MULTIPLIER if repeat_multiplier is None else repeat_multiplier
    total = 0
    # A call that never resolved has no capability, and repeats of it still count:
    # trying the same unbound tool again is the same signal as retrying a refused one.
    seen: set[tuple[Capability | None, str]] = set()
    for event in events:
        if event.effect is not Effect.DENY:
            continue
        key = (event.capability, event.resource)
        total += event.weight * (multiplier if key in seen else 1)
        seen.add(key)
    return total
