"""Nonsecret retained storage evidence required before removing pair compute."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from ads_sandbox_manager.egress_state_objects import identity
from ads_sandbox_manager.egress_state_store import state_from_snapshot
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_volume_inputs import VOLUME_ROLES
from ads_sandbox_manager.session_objects import ca_consumer_name, ipc_name, session_name


def storage_targets(snapshot: Object, retain_workspace: bool) -> dict[str, Object]:
    sandbox = UUID(snapshot["sandbox_id"])
    result = {}
    for role in VOLUME_ROLES:
        entry = snapshot["volume_resources"][role]
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
    result["ipc"] = {
        "kind": "PersistentVolumeClaim",
        "name": ipc_name(sandbox),
        "uid": snapshot["ipc_resources"]["volume"]["uid"],
        "retain": False,
    }
    if snapshot["egress_state"] is None:
        raise RuntimeError("persistent pair storage ownership required")
    state = state_from_snapshot(snapshot["egress_state"])
    result["state"] = {
        "kind": "PersistentVolumeClaim",
        "name": identity(state, "volume")["metadata"]["name"],
        "uid": state.volume_uid,
        "retain": retain_workspace,
    }
    if any(not isinstance(t["uid"], str) or not t["uid"].strip() for t in result.values()):
        raise RuntimeError("complete captured volume UIDs required")
    return result


def validate_storage_capture(target: Object, evidence: Object) -> None:
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
                for key in ("pv_name", "pv_uid", "volume_key", "observed_at")
            )
        ):
            raise ValueError
        observed = datetime.fromisoformat(evidence["observed_at"])
        if observed.tzinfo is None or observed.isoformat() != evidence["observed_at"]:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("incomplete or changed pre-teardown storage capture") from None
