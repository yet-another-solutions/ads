from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import msgspec

from ads_commons.security import (
    Identity,
    identity_from_claims,
    roles_from_claims,
    security_context_from_identity,
)

__all__ = [
    "Identity",
    "identity_from_claims",
    "identity_from_session",
    "roles_from_claims",
    "security_context_from_identity",
]


def identity_from_session(session: Mapping[str, Any] | None) -> Identity | None:
    if not session:
        return None
    raw = session.get("identity")
    if not isinstance(raw, dict):
        return None
    try:
        return msgspec.convert(raw, type=Identity)
    except (msgspec.ValidationError, TypeError, ValueError):
        return None
