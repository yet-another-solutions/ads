"""Fixed fresh workspace and CA clone inputs; no legacy adoption or resume."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from kubernetes.utils.quantity import parse_quantity

from ads_sandbox_manager.ca_objects import ca_metadata
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import JOB_UID, Object
from ads_sandbox_manager.pair_objects import PROJECT, PairBinding
from ads_sandbox_manager.session_objects import CA_CONSUMERS, ca_consumer_pvc, session_pvc

VOLUME_ROLES = ("workspace", "guest", "egress", "key")


def volume_role(role: str) -> None:
    if role not in VOLUME_ROLES:
        raise ValueError("unsupported paired clone role")


def new_volume_resources() -> dict[str, Any]:
    return {role: {"payload": None, "uid": None, "dispatch": "unissued"} for role in VOLUME_ROLES}


def source_snapshot(settings: Settings, role: str, obj: Object) -> Object:
    """Retain only nonsecret fixed identity/capacity, not arbitrary API metadata."""
    name = settings.golden_name if role == "workspace" else ca_metadata(settings, role)["name"]
    try:
        meta, spec = obj["metadata"], obj["spec"]
        requested = parse_quantity(spec["resources"]["requests"]["storage"])
        capacity = parse_quantity(
            obj.get("status", {}).get("capacity", {}).get("storage", str(requested))
        )
        size = max(requested, capacity)
        uid, job = meta["uid"], meta["labels"][JOB_UID]
        if (
            meta["name"] != name
            or meta["namespace"] != settings.namespace
            or meta.get("deletionTimestamp")
            or meta.get("ownerReferences")
            or spec["volumeMode"] != "Block"
            or spec["storageClassName"] != "sandbox-block"
            or spec["accessModes"] != ["ReadWriteOnce"]
            or not isinstance(uid, str)
            or not uid.strip()
            or not isinstance(job, str)
            or str(UUID(job)) != job
            or size != int(size)
            or not 0 < size < 2**63
        ):
            raise ValueError
    except (KeyError, ValueError, TypeError, ArithmeticError):
        raise RuntimeError("invalid verified clone source") from None
    return {"name": name, "uid": uid, "job_uid": job, "storage_bytes": int(size)}


def validate_volume_payload(role: str, payload: object) -> None:
    volume_role(role)
    try:
        if not isinstance(payload, dict) or set(payload) != {
            "pvc_id",
            "pvc_changed",
            "sources",
            "manifest",
        }:
            raise ValueError
        changed = datetime.fromisoformat(payload["pvc_changed"])
        if changed.tzinfo is None or changed.isoformat() != payload["pvc_changed"]:
            raise ValueError
        if (
            not isinstance(payload["pvc_id"], str)
            or str(UUID(payload["pvc_id"])) != payload["pvc_id"]
        ):
            raise ValueError
        sources = payload["sources"]
        if (
            not isinstance(sources, dict)
            or set(sources) != ({"workspace"} if role == "workspace" else {"public", "private"})
            or not isinstance(payload["manifest"], dict)
        ):
            raise ValueError
        for value in sources.values():
            if (
                not isinstance(value, dict)
                or set(value) != {"name", "uid", "job_uid", "storage_bytes"}
                or any(
                    not isinstance(value[key], str) or not value[key].strip()
                    for key in ("name", "uid", "job_uid")
                )
                or str(UUID(value["job_uid"])) != value["job_uid"]
                or type(value["storage_bytes"]) is not int
                or not 0 < value["storage_bytes"] < 2**63
            ):
                raise ValueError
        if role != "workspace" and (
            sources["public"]["job_uid"] != sources["private"]["job_uid"]
            or sources["public"]["uid"] == sources["private"]["uid"]
        ):
            raise ValueError
    except (KeyError, ValueError, TypeError, AttributeError):
        raise RuntimeError("corrupt paired clone payload") from None


def validate_volume_resources(value: object) -> None:
    if not isinstance(value, dict) or set(value) != set(VOLUME_ROLES):
        raise RuntimeError("corrupt paired clone resources")
    for role, entry in value.items():
        if not isinstance(entry, dict) or set(entry) != {"payload", "uid", "dispatch"}:
            raise RuntimeError("corrupt paired clone resource")
        if entry["dispatch"] == "unissued":
            if entry != new_volume_resources()[role]:
                raise RuntimeError("corrupt unissued paired clone")
            continue
        if entry["dispatch"] not in ("inflight", "settled") or (
            entry["uid"] is not None
            and (not isinstance(entry["uid"], str) or not entry["uid"].strip())
        ):
            raise RuntimeError("corrupt paired clone dispatch")
        validate_volume_payload(role, entry["payload"])


def volume_manifest(settings: Settings, pair: PairBinding, role: str, payload: Object) -> Object:
    volume_role(role)
    if role == "workspace":
        source = payload["sources"]["workspace"]
        if source["name"] != settings.golden_name:
            raise RuntimeError("workspace clone source name changed")
        desired = session_pvc(
            settings,
            pair.session_id,
            pair.sandbox_id,
            settings.golden_version,
            str(source["storage_bytes"]),
            UUID(payload["pvc_id"]),
        )
    else:
        sources = payload["sources"]
        if any(
            sources[key]["name"] != ca_metadata(settings, key)["name"]
            for key in ("public", "private")
        ):
            raise RuntimeError("CA clone source name changed")
        source = sources[CA_CONSUMERS[role]]
        desired = ca_consumer_pvc(
            settings,
            pair.session_id,
            pair.sandbox_id,
            settings.golden_version,
            role,
            {
                "metadata": {
                    "name": source["name"],
                    "uid": source["uid"],
                    "labels": {JOB_UID: source["job_uid"]},
                },
                "spec": {"resources": {"requests": {"storage": str(source["storage_bytes"])}}},
            },
        )
    desired["metadata"]["labels"][PROJECT] = str(pair.project_id)
    if "manifest" in payload:
        validate_volume_payload(role, payload)
        if desired != payload["manifest"]:
            raise RuntimeError("committed paired clone manifest changed")
    return desired
