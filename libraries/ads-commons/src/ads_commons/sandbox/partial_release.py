"""Exact partial private-runtime reports, distinct from full-pair inventories."""

from __future__ import annotations

import json
from typing import Annotated, Literal
from uuid import UUID

import msgspec

from ads_commons.sandbox.node_release import Name, NodeReleaseLeftovers, _unique

Role = Literal["guest", "egress", "guest-relay", "egress-relay"]


class PartialReleaseReport(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    schema: Literal["ads-partial-release-v1"]
    node: Name
    namespace: Name
    network: Name
    generation: UUID
    sandbox_id: UUID
    boot_id: UUID
    pod_uids: dict[Role, UUID]
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
            not 1 <= len(self.pod_uids) <= 4
            or len(set(self.pod_uids.values())) != len(self.pod_uids)
            or self.attachment_admission_fenced is not True
            or self.release_inventory_captured is not True
            or self.generation_retired is not False
            or self.observed_runtime_released
            != (self.leftovers is not None and self.leftovers.clear())
        ):
            raise ValueError("inconsistent partial release report")


def decode_partial_release(raw: bytes) -> PartialReleaseReport:
    if type(raw) is not bytes or not 0 < len(raw) <= 16384:
        raise ValueError("bounded partial report bytes required")
    return msgspec.convert(
        json.loads(raw, object_pairs_hook=_unique), type=PartialReleaseReport, strict=True
    )
