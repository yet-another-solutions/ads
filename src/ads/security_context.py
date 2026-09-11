from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Request-bound identity. Pass this object; do not store it in contextvars."""

    subject: str
    name: str
    roles: frozenset[str]
    email: str | None = None

    def has_role(self, role: str) -> bool:
        return role in self.roles
