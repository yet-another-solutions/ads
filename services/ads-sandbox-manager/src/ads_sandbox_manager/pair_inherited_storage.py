"""Compose retired original release with a successor that never attached."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import TYPE_CHECKING
from uuid import UUID

import msgspec

from ads_commons.sandbox.block_release import decode_block_release
from ads_sandbox_manager.objects import Object

if TYPE_CHECKING:
    from ads_sandbox_manager.pair_retirement import PairRetirement


def inherited_capture(saved: PairRetirement, role: str, *, retain: bool) -> Object:
    """Only a verified retirement passed by the claim-owning repository caller."""
    if role not in ("workspace", "state") or saved.kind != "idle":
        raise RuntimeError("inherited storage requires an idle-retired lifetime")
    journal = saved.journal
    unused = journal["unused_storage"].get(role)
    original = (
        journal["storage_capture"].get(role)
        or journal["partial_storage"].get(role)
        or (unused["capture"]["target"] if unused else None)
    )
    if original is None or not original["retain"] or not original.get("volume_key"):
        raise RuntimeError("inherited original CSI release target required")
    if journal["block_disposition"].get(role) == "retained":
        block, never = journal["block_capture"], False
    elif unused is not None and unused["disposition"] == "retained":
        if unused["capture"]["mode"] == "retired-inherited-csi":
            block = unused["capture"]["previous"]["block_capture"]
            never = unused["capture"]["previous"]["never_mounted"]
        elif unused["capture"]["mode"] == "never-mounted-csi":
            block, never = None, True
        else:
            raise RuntimeError("unsupported inherited original release")
    else:
        raise RuntimeError("inherited original release remains incomplete")
    return {
        "mode": "retired-inherited-csi",
        "target": {**deepcopy(original), "retain": retain},
        "storage_class": None,
        "pvc_created": None,
        "previous": {
            "generation": str(saved.generation),
            "retirement_sha256": saved.journal_sha256,
            "block_capture": deepcopy(block),
            "never_mounted": never,
        },
    }


def validate_inherited_capture(journal: Object, role: str, value: Object) -> None:
    previous, target = value["previous"], value["target"]
    if (
        role not in ("workspace", "state")
        or not isinstance(previous, dict)
        or set(previous) != {"generation", "retirement_sha256", "block_capture", "never_mounted"}
        or previous["generation"] != journal["snapshot"]["retained_from"]
        or not isinstance(previous["generation"], str)
        or str(UUID(previous["generation"])) != previous["generation"]
        or previous["generation"] == journal["snapshot"]["generation"]
        or not isinstance(previous["retirement_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", previous["retirement_sha256"]) is None
        or type(previous["never_mounted"]) is not bool
        or previous["never_mounted"] != (previous["block_capture"] is None)
        or target.get("never_bound")
        or not target.get("volume_key")
        or target.get("filesystem_backing")
        or not (target["retain"] or (target["delete_policy"] and target["reclaim_guard"]))
        or value["storage_class"] is not None
        or value["pvc_created"] is not None
    ):
        raise RuntimeError("inherited storage lacks original retired release provenance")
    if previous["never_mounted"]:
        if target["nodes"]:
            raise RuntimeError("original never-mounted target has contradictory node use")
        return
    captured = decode_block_release(msgspec.json.encode(previous["block_capture"]))
    identity = captured.volumes.get(role)
    if (
        identity is None
        or captured.leftovers is not None
        or captured.released
        or captured.node not in target["nodes"]
        or captured.namespace != journal["snapshot"]["namespace"]
        or str(captured.sandbox_id) != journal["snapshot"]["sandbox_id"]
        or str(identity.volume_uid) != target["uid"]
        or str(identity.pv_uid) != target["pv_uid"]
        or identity.name != target["name"]
        or identity.pv_name != target["pv_name"]
        or identity.volume_key != target["volume_key"]
    ):
        raise RuntimeError("inherited original Block capture changed")


def validate_inherited_release(value: Object) -> None:
    captured = value["capture"]["previous"]["block_capture"]
    raw = value["release"]
    if raw is not None:
        report = decode_block_release(msgspec.json.encode(raw))
        if (
            captured is None
            or not report.released
            or any(
                raw[key] != captured[key]
                for key in captured
                if key not in ("leftovers", "released")
            )
        ):
            raise RuntimeError("inherited Block observation differs from original inventory")
    if value["disposition"] is not None and captured is not None and raw is None:
        raise RuntimeError("inherited Block disposition lacks fresh original release")
