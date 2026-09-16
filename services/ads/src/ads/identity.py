from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import msgspec

from ads_commons.security import (
    Identity,
    SecurityContext,
    identity_from_claims,
    roles_from_claims,
    security_context_from_identity,
)

ACCESS_TOKEN_SESSION_KEY = "access_token"

__all__ = [
    "ACCESS_TOKEN_SESSION_KEY",
    "Identity",
    "access_token_from_session",
    "identity_from_claims",
    "identity_from_session",
    "roles_from_claims",
    "security_context_from_identity",
    "security_context_from_session",
    "session_is_authenticated",
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


def access_token_from_session(session: Mapping[str, Any] | None) -> str | None:
    if not session:
        return None
    raw = session.get(ACCESS_TOKEN_SESSION_KEY)
    if isinstance(raw, str) and raw.strip():
        return raw
    return None


def session_is_authenticated(session: Mapping[str, Any] | None) -> bool:
    return (
        identity_from_session(session) is not None
        and access_token_from_session(session) is not None
    )


def security_context_from_session(session: Mapping[str, Any] | None) -> SecurityContext | None:
    identity = identity_from_session(session)
    if identity is None:
        return None
    token = access_token_from_session(session)
    if token is None:
        return None
    return security_context_from_identity(identity).with_access_token(token)
