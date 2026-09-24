"""Trusted node observer reports; authentication and lifecycle authority are separate."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal
from uuid import UUID

import msgspec

Count = Annotated[int, msgspec.Meta(ge=0, le=2147483647)]
Name = Annotated[str, msgspec.Meta(min_length=1, max_length=253)]


class NodeReleaseLeftovers(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    pods: Count
    ready_sandboxes: Count
    live_containers: Count
    journals: Count
    host_links: Count
    process_namespace_references: Count

    def clear(self) -> bool:
        return not any(msgspec.structs.astuple(self))


class NodeReleaseReport(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    schema: Literal["ads-node-release-v1"]
    node: Name
    namespace: Name
    network: Name
    generation: UUID
    sandbox_id: UUID
    boot_id: UUID
    pod_uids: tuple[UUID, UUID, UUID, UUID]
    inventory_sha256: Annotated[
        str, msgspec.Meta(min_length=64, max_length=64, pattern="^[0-9a-f]{64}$")
    ]
    attachment_admission_fenced: bool
    release_inventory_captured: bool
    observed_runtime_released: bool
    generation_retired: bool
    leftovers: NodeReleaseLeftovers | None

    def __post_init__(self) -> None:
        if (
            self.attachment_admission_fenced is not True
            or self.release_inventory_captured is not True
            or self.generation_retired is not False
            or len(set(self.pod_uids)) != 4
            or (
                self.observed_runtime_released
                != (self.leftovers is not None and self.leftovers.clear())
            )
        ):
            raise ValueError("inconsistent node release report")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate node report field")
        result[key] = value
    return result


def decode_node_release(raw: bytes) -> NodeReleaseReport:
    if type(raw) is not bytes or not 0 < len(raw) <= 16384:
        raise ValueError("bounded node report bytes required")
    return msgspec.convert(
        json.loads(raw, object_pairs_hook=_unique), type=NodeReleaseReport, strict=True
    )
