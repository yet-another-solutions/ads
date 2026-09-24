"""Application-node IPC proof, deliberately distinct from private-pair reports."""

from __future__ import annotations

import json
from typing import Annotated, Literal
from uuid import UUID

import msgspec

from ads_commons.sandbox.node_release import Count, Name, _unique


class IpcReleaseLeftovers(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    pods: Count
    ready_sandboxes: Count
    live_containers: Count
    process_references: Count
    mount_references: Count

    def clear(self) -> bool:
        return not any(msgspec.structs.astuple(self))


class IpcReleaseReport(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    schema: Literal["ads-ipc-release-v1"]
    node: Name
    namespace: Name
    generation: UUID
    sandbox_id: UUID
    boot_id: UUID
    pod_uid: UUID
    volume_uid: UUID
    inventory_sha256: Annotated[
        str, msgspec.Meta(min_length=64, max_length=64, pattern="^[0-9a-f]{64}$")
    ]
    release_inventory_captured: bool
    observed_runtime_released: bool
    leftovers: IpcReleaseLeftovers | None

    def __post_init__(self) -> None:
        if self.release_inventory_captured is not True or (
            self.observed_runtime_released
            != (self.leftovers is not None and self.leftovers.clear())
        ):
            raise ValueError("inconsistent IPC release report")


def decode_ipc_release(raw: bytes) -> IpcReleaseReport:
    if type(raw) is not bytes or not 0 < len(raw) <= 16384:
        raise ValueError("bounded IPC report bytes required")
    return msgspec.convert(
        json.loads(raw, object_pairs_hook=_unique), type=IpcReleaseReport, strict=True
    )
