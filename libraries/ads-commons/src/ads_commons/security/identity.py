from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

import msgspec

from ads_commons.security.context import SecurityContext


class Identity(msgspec.Struct, frozen=True):
    sub: str
    name: str
    roles: tuple[str, ...]
    email: str | None = None
    azp: str | None = None


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
        raise ValueError("token missing sub")
    try:
        UUID(subject)
    except ValueError as exc:
        raise ValueError("sub must be a UUID") from exc
    name = payload.get("name") or payload.get("preferred_username") or subject
    email = payload.get("email")
    azp = payload.get("azp")
    return Identity(
        sub=subject,
        name=str(name),
        roles=roles_from_claims(payload, client_id),
        email=str(email) if isinstance(email, str) else None,
        azp=azp if isinstance(azp, str) and azp else None,
    )


def security_context_from_identity(identity: Identity) -> SecurityContext:
    return SecurityContext(
        subject=identity.sub,
        name=identity.name,
        roles=frozenset(identity.roles),
        email=identity.email,
        authorized_party=identity.azp,
    )
