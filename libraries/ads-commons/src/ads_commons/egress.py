"""Project egress wire contracts. Enforcement and orchestration belong to services."""

from __future__ import annotations

import re
from typing import Annotated, Literal, Protocol
from uuid import UUID

import msgspec

EgressMode = Literal["whitelist", "blacklist"]
HttpMethod = Literal[
    "any", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
]
UpgradeTarget = Literal["http/2", "websocket"]
SubProtocol = Literal["any", "http/1.1", "http/2", "websocket"]
Port = Annotated[int, msgspec.Meta(ge=1, le=65535)]
Revision = Annotated[int, msgspec.Meta(ge=1, le=9223372036854775807)]
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


class EgressPath(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    pattern: Annotated[str, msgspec.Meta(min_length=1, max_length=8192)]
    case_insensitive: bool | msgspec.UnsetType = msgspec.UNSET

    def __post_init__(self) -> None:
        if not self.pattern.startswith("/") or "\x00" in self.pattern:
            raise ValueError("path pattern must start with / and contain no NUL")


class ProtocolSettings(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    method: HttpMethod
    upgrades: (
        Literal["any", "none"]
        | Annotated[tuple[UpgradeTarget, ...], msgspec.Meta(min_length=1, max_length=2)]
    )
    paths: Annotated[tuple[EgressPath, ...], msgspec.Meta(max_length=256)] = ()

    def __post_init__(self) -> None:
        if isinstance(self.upgrades, tuple) and len(set(self.upgrades)) != len(self.upgrades):
            raise ValueError("upgrade targets must be unique")


class EgressRule(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    domain: Annotated[str, msgspec.Meta(min_length=1, max_length=253)]
    port: Port
    protocol: Literal["http", "https"]
    protocol_settings: ProtocolSettings
    sub_protocol: SubProtocol = "any"

    def __post_init__(self) -> None:
        if self.domain == "*":
            return
        value = self.domain.lower()
        name = value[2:] if value.startswith("*.") else value
        if not all(_LABEL.fullmatch(label) for label in name.split(".")):
            raise ValueError("domain must be an ASCII DNS name, *, or *.suffix")
        # Explicit ASCII A-labels are accepted. No implicit Unicode/IDNA remapping.
        msgspec.structs.force_setattr(self, "domain", value)


class ProjectEgressSettings(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    rules: Annotated[tuple[EgressRule, ...], msgspec.Meta(max_length=1024)]
    mode: EgressMode = "whitelist"


class ProjectEgressSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    revision: Revision
    settings: ProjectEgressSettings


class ProjectEgressApi(Protocol):
    async def get_egress(self, project_id: UUID) -> ProjectEgressSnapshot: ...

    async def save_egress(
        self, project_id: UUID, settings: ProjectEgressSettings
    ) -> ProjectEgressSnapshot: ...

    async def delete_egress(self, project_id: UUID) -> None: ...


EGRESS_CONFIG_TOPIC = "ads.sandbox.egress.config"


class EgressConfigRequest(
    msgspec.Struct, frozen=True, forbid_unknown_fields=True, tag="config-request"
):
    project_id: UUID
    sandbox_id: UUID


class EgressConfigUpdate(
    msgspec.Struct, frozen=True, forbid_unknown_fields=True, tag="config-update"
):
    project_id: UUID
    snapshot: ProjectEgressSnapshot


EgressConfigMessage = EgressConfigRequest | EgressConfigUpdate


class EgressApply(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    project_id: UUID
    snapshot: ProjectEgressSnapshot


class EgressApplied(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    instance_id: UUID
    revision: Revision


class EgressPing(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    instance_id: UUID
    healthy: bool


class EgressStale(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    code: Literal["stale_revision"]
    received_revision: Revision
    applied_revision: Revision


class EgressStaleResponse(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    error: EgressStale


class SandboxProjectBinding(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    sandbox_id: UUID
    session_id: UUID
    project_id: UUID
    eligible: bool


class ServiceOriginTokens(Protocol):
    def exchange_service(self, audience: str) -> str: ...


def canonical_settings(settings: ProjectEgressSettings) -> ProjectEgressSettings:
    """Expand semantic defaults for equality; retain rule/path order and never lint intent."""
    settings = msgspec.json.decode(msgspec.json.encode(settings), type=ProjectEgressSettings)
    return msgspec.structs.replace(
        settings,
        rules=tuple(
            msgspec.structs.replace(
                rule,
                protocol_settings=msgspec.structs.replace(
                    rule.protocol_settings,
                    upgrades=(
                        tuple(sorted(rule.protocol_settings.upgrades))
                        if isinstance(rule.protocol_settings.upgrades, tuple)
                        else rule.protocol_settings.upgrades
                    ),
                    paths=tuple(
                        msgspec.structs.replace(
                            path,
                            case_insensitive=(
                                settings.mode == "blacklist"
                                if path.case_insensitive is msgspec.UNSET
                                else path.case_insensitive
                            ),
                        )
                        for path in rule.protocol_settings.paths
                    ),
                ),
            )
            for rule in settings.rules
        ),
    )
