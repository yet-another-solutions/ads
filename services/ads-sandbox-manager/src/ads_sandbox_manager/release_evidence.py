"""Stored bound-PV release identity: captured once while the claim is alive.

The evidence dict is exactly one of:
  {"captured": True, "never_bound": True}
  {"captured": True, "pv_name": str, "pv_uid": str, "volume_key": str | None}
Nothing else belongs here: node observations and reclaim-policy fields are
runtime/driver state, not stored identity. Teardown consumes this evidence
verbatim and never derives it during deletion.
"""

from __future__ import annotations

from typing import Any

RELEASE_FIELDS = {"captured", "pv_name", "pv_uid", "volume_key"}
NEVER_BOUND_FIELDS = {"captured", "never_bound"}


def validate_release(value: object) -> None:
    """None means not captured yet; anything present must be the exact shape."""
    if value is None:
        return
    if not isinstance(value, dict) or value.get("captured") is not True:
        raise RuntimeError("corrupt release evidence")
    if set(value) == NEVER_BOUND_FIELDS:
        if value["never_bound"] is not True:
            raise RuntimeError("corrupt release evidence")
        return
    if set(value) != RELEASE_FIELDS:
        raise RuntimeError("corrupt release evidence")
    if any(
        not isinstance(value[field], str) or not value[field].strip()
        for field in ("pv_name", "pv_uid")
    ):
        raise RuntimeError("corrupt release evidence")
    if value["volume_key"] is not None and (
        not isinstance(value["volume_key"], str) or not value["volume_key"].strip()
    ):
        raise RuntimeError("corrupt release evidence")


def bind_release(entry: dict[str, Any], release: dict[str, Any]) -> dict[str, Any]:
    """First-wins attachment: stored identity never changes after capture."""
    validate_release(release)
    current = entry.get("release")
    if current is not None:
        if current != release:
            raise RuntimeError("stored release evidence changed")
        return entry
    return {**entry, "release": release}
