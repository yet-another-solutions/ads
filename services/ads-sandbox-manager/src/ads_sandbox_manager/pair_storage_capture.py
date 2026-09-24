"""Nonsecret retained storage evidence required before removing pair compute."""

from __future__ import annotations

from datetime import datetime
from pathlib import PurePosixPath
from uuid import UUID

from ads_sandbox_manager.egress_state_objects import identity
from ads_sandbox_manager.egress_state_store import state_from_snapshot
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_volume_inputs import VOLUME_ROLES
from ads_sandbox_manager.session_objects import ca_consumer_name, ipc_name, session_name


def storage_targets(
    snapshot: Object, retain_workspace: bool, *, issued_only: bool = False
) -> dict[str, Object]:
    sandbox = UUID(snapshot["sandbox_id"])
    result = {}
    for role in VOLUME_ROLES:
        entry = snapshot["volume_resources"][role]
        if issued_only and entry["dispatch"] == "unissued" and entry["uid"] is None:
            continue
        if entry["payload"] is None:
            raise RuntimeError("full pair storage ownership required before compute teardown")
        name = (
            session_name(UUID(entry["payload"]["pvc_id"]))
            if role == "workspace"
            else ca_consumer_name(sandbox, role)
        )
        result[role] = {
            "kind": "PersistentVolumeClaim",
            "name": name,
            "uid": entry["uid"],
            "retain": role == "workspace" and retain_workspace,
        }
    ipc = snapshot["ipc_resources"]["volume"]
    if not issued_only or ipc["dispatch"] != "unissued" or ipc["uid"] is not None:
        result["ipc"] = {
            "kind": "PersistentVolumeClaim",
            "name": ipc_name(sandbox),
            "uid": ipc["uid"],
            "retain": False,
        }
    if snapshot["egress_state"] is None:
        if not issued_only:
            raise RuntimeError("persistent pair storage ownership required")
    else:
        state = state_from_snapshot(snapshot["egress_state"])
        if not issued_only or state.volume_dispatch != "unissued" or state.volume_uid is not None:
            result["state"] = {
                "kind": "PersistentVolumeClaim",
                "name": identity(state, "volume")["metadata"]["name"],
                "uid": state.volume_uid,
                "retain": retain_workspace,
            }
    if any(not isinstance(t["uid"], str) or not t["uid"].strip() for t in result.values()):
        raise RuntimeError("complete captured volume UIDs required")
    return result


def validate_storage_observation(target: Object, evidence: Object) -> None:
    """Retain pre-runtime-removal facts, explicitly not release/reclamation proof.

    Pending/unbound and filesystem volumes are valid observations. They cannot
    satisfy the strict complete bound-CSI capture contract below or authorize
    PVC deletion. A later binding and actual driver/storage release still need
    their own evidence before disposition.
    """
    try:
        common = {*target, "captured", "nodes", "observed_at"}
        if (
            not isinstance(evidence, dict)
            or any(evidence.get(key) != value for key, value in target.items())
            or evidence.get("captured") is not True
            or not isinstance(evidence.get("nodes"), list)
            or any(not isinstance(node, str) or not node.strip() for node in evidence["nodes"])
            or len(set(evidence["nodes"])) != len(evidence["nodes"])
            or not isinstance(evidence.get("observed_at"), str)
            or datetime.fromisoformat(evidence["observed_at"]).tzinfo is None
        ):
            raise ValueError
        if "never_bound" in evidence:
            if set(evidence) != common | {"never_bound"} or evidence["never_bound"] is not True:
                raise ValueError
        elif (
            set(evidence)
            != common
            | {"pv_name", "pv_uid", "delete_policy", "volume_key", "reclaim_guard"}
            | ({"filesystem_backing"} if "filesystem_backing" in evidence else set())
            or any(
                not isinstance(evidence[key], str) or not evidence[key].strip()
                for key in ("pv_name", "pv_uid")
            )
            or type(evidence["delete_policy"]) is not bool
            or type(evidence["reclaim_guard"]) is not bool
            or (
                evidence["volume_key"] is not None
                and (
                    not isinstance(evidence["volume_key"], str)
                    or not evidence["volume_key"].strip()
                )
            )
        ):
            raise ValueError
        if "filesystem_backing" in evidence:
            validate_filesystem_backing(evidence)
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("incomplete original partial storage observation") from None


def validate_filesystem_backing(evidence: Object) -> None:
    backing = evidence["filesystem_backing"]
    if (
        not isinstance(backing, dict)
        or set(backing) != {"source", "path"}
        or backing["source"] not in ("local", "hostPath")
        or evidence["volume_key"] is not None
        or not isinstance(backing["path"], str)
        or not backing["path"].startswith("/")
        or backing["path"] == "/"
        or str(PurePosixPath(backing["path"])) != backing["path"]
        or ".." in PurePosixPath(backing["path"]).parts
    ):
        raise ValueError("invalid original filesystem backing identity")


def validate_storage_capture(target: Object, evidence: Object, *, filesystem: bool = False) -> None:
    """Require bound-volume/node evidence; never invent a never-mounted shortcut."""
    fields = {
        *target,
        "captured",
        "nodes",
        "observed_at",
        "pv_name",
        "pv_uid",
        "delete_policy",
        "volume_key",
        "reclaim_guard",
    }
    try:
        local = "filesystem_backing" in evidence
        if local:
            if not filesystem:
                raise ValueError
            validate_filesystem_backing(evidence)
            fields.add("filesystem_backing")
        if (
            not isinstance(evidence, dict)
            or set(evidence) != fields
            or any(evidence[key] != value for key, value in target.items())
            or evidence["captured"] is not True
            or type(evidence["retain"]) is not bool
            or type(evidence["delete_policy"]) is not bool
            or type(evidence["reclaim_guard"]) is not bool
            or not isinstance(evidence["nodes"], list)
            or not evidence["nodes"]
            or any(not isinstance(node, str) or not node.strip() for node in evidence["nodes"])
            or len(set(evidence["nodes"])) != len(evidence["nodes"])
            or any(
                not isinstance(evidence[key], str) or not evidence[key].strip()
                for key in (
                    "pv_name",
                    "pv_uid",
                    "observed_at",
                    *(("volume_key",) if not local else ()),
                )
            )
        ):
            raise ValueError
        observed = datetime.fromisoformat(evidence["observed_at"])
        if observed.tzinfo is None or observed.isoformat() != evidence["observed_at"]:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("incomplete or changed pre-teardown storage capture") from None
