"""Node-owned original CSI Block-device use proof."""

from __future__ import annotations

import json
from typing import Literal
from uuid import UUID

import msgspec

from ads_commons.sandbox.ipc_storage import Digest
from ads_commons.sandbox.node_release import Count, Name, _unique


class BlockVolumeIdentity(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    name: Name
    volume_uid: UUID
    pv_name: Name
    pv_uid: UUID
    pod_uid: UUID
    volume_key: Name


class BlockReleaseCounts(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    mappings: Count
    mounts: Count
    descriptors: Count
    holders: Count

    def clear(self) -> bool:
        return not any(msgspec.structs.astuple(self))


class BlockReleaseReport(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    schema: Literal["ads-block-release-v1"]
    node: Name
    namespace: Name
    network: Name
    generation: UUID
    sandbox_id: UUID
    boot_id: UUID
    runtime_sha256: Digest
    inventory_sha256: Digest
    volumes: dict[str, BlockVolumeIdentity]
    leftovers: BlockReleaseCounts | None
    released: bool

    def __post_init__(self) -> None:
        if (
            not self.volumes
            or not set(self.volumes) <= {"workspace", "guest", "egress", "key", "state"}
            or len({v.volume_uid for v in self.volumes.values()}) != len(self.volumes)
            or len({v.pv_uid for v in self.volumes.values()}) != len(self.volumes)
            or len({v.volume_key for v in self.volumes.values()}) != len(self.volumes)
            or self.released != (self.leftovers is not None and self.leftovers.clear())
        ):
            raise ValueError("inconsistent original block release report")


def decode_block_release(raw: bytes) -> BlockReleaseReport:
    if type(raw) is not bytes or not 0 < len(raw) <= 16384:
        raise ValueError("bounded block release report required")
    return msgspec.convert(
        json.loads(raw, object_pairs_hook=_unique), type=BlockReleaseReport, strict=True
    )
