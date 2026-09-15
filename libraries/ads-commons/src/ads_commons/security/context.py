from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from uuid import UUID


def _empty_attributes() -> Mapping[str, object]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Identity bound to the current request or detached work."""

    subject: str
    name: str
    roles: frozenset[str]
    email: str | None = None
    authorized_party: str | None = None
    attributes: Mapping[str, object] = field(default_factory=_empty_attributes)

    @property
    def user_id(self) -> UUID:
        return UUID(self.subject)

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_caller(self, *allowed: str) -> bool:
        return self.authorized_party is not None and self.authorized_party in allowed

    def attribute(self, key: str) -> object | None:
        return self.attributes.get(key)

    def with_attributes(
        self,
        extra: Mapping[str, object] | None = None,
        **values: object,
    ) -> SecurityContext:
        merged: dict[str, object] = dict(self.attributes)
        if extra:
            merged.update(extra)
        merged.update(values)
        return replace(self, attributes=MappingProxyType(merged))
