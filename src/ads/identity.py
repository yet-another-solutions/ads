from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import msgspec

from ads.security_context import SecurityContext


class Identity(msgspec.Struct, frozen=True):
    sub: str
    name: str
    roles: tuple[str, ...]
    email: str | None = None


def roles_from_claims(payload: Mapping[str, Any], client_id: str) -> tuple[str, ...]:
    roles: set[str] = set()
    realm_access = payload.get("realm_access")
    if isinstance(realm_access, Mapping):
        realm_roles = realm_access.get("roles")
        if isinstance(realm_roles, list):
            roles.update(str(item) for item in realm_roles)
    resource_access = payload.get("resource_access")
    if isinstance(resource_access, Mapping):
        client_access = resource_access.get(client_id)
        if isinstance(client_access, Mapping):
            client_roles = client_access.get("roles")
            if isinstance(client_roles, list):
                roles.update(str(item) for item in client_roles)
    return tuple(sorted(roles))


def identity_from_claims(payload: Mapping[str, Any], client_id: str) -> Identity:
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError("id token missing sub")
    name = payload.get("name") or payload.get("preferred_username") or subject
    email = payload.get("email")
    return Identity(
        sub=subject,
        name=str(name),
        roles=roles_from_claims(payload, client_id),
        email=str(email) if isinstance(email, str) else None,
    )


def security_context_from_identity(identity: Identity) -> SecurityContext:
    return SecurityContext(
        subject=identity.sub,
        name=identity.name,
        roles=frozenset(identity.roles),
        email=identity.email,
    )


def identity_from_session(session: Mapping[str, Any]) -> Identity | None:
    raw = session.get("identity")
    if not isinstance(raw, dict):
        return None
    try:
        return msgspec.convert(raw, type=Identity)
    except (TypeError, msgspec.ValidationError):
        return None
