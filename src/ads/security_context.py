from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Identity bound to the current HTTP request or detached work."""

    subject: str
    name: str
    roles: frozenset[str]
    email: str | None = None

    def has_role(self, role: str) -> bool:
        return role in self.roles
