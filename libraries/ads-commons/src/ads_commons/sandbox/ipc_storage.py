"""Trusted native IPC backing observations, separate from runtime release."""

from __future__ import annotations

import json
from typing import Annotated, Literal
from uuid import UUID

import msgspec

from ads_commons.sandbox.node_release import Name, _unique

Digest = Annotated[str, msgspec.Meta(min_length=64, max_length=64, pattern="^[0-9a-f]{64}$")]


class IpcStorageReport(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    schema: Literal["ads-ipc-storage-v1"]
    node: Name
    namespace: Name
    generation: UUID
    sandbox_id: UUID
    boot_id: UUID
    pod_uid: UUID
    volume_uid: UUID
    pv_uid: UUID
    runtime_sha256: Digest
    inventory_sha256: Digest
    observed: bool
    released: bool
    reclaimed: bool

    def __post_init__(self) -> None:
        if (self.released and not self.observed) or (self.reclaimed and not self.released):
            raise ValueError("inconsistent IPC storage report")


def decode_ipc_storage(raw: bytes) -> IpcStorageReport:
    if type(raw) is not bytes or not 0 < len(raw) <= 16384:
        raise ValueError("bounded IPC storage report required")
    return msgspec.convert(
        json.loads(raw, object_pairs_hook=_unique), type=IpcStorageReport, strict=True
    )
