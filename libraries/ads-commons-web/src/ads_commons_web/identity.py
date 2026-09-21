from __future__ import annotations

from collections.abc import Mapping
from typing import Any

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
    "identity_from_security_context",
    "initials",
    "roles_from_claims",
    "security_context_from_identity",
]


def access_token_from_session(session: Mapping[str, Any] | None) -> str | None:
    if not session:
        return None
    raw = session.get(ACCESS_TOKEN_SESSION_KEY)
    if isinstance(raw, str) and raw.strip():
        return raw
    return None


def initials(name: str) -> str:
    parts = [part for part in name.split() if part]
    if not parts:
        return "AD"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def identity_from_security_context(context: SecurityContext) -> Identity:
    return Identity(
        sub=context.subject,
        name=context.name,
        roles=tuple(sorted(context.roles)),
        email=context.email,
        azp=context.authorized_party,
    )
