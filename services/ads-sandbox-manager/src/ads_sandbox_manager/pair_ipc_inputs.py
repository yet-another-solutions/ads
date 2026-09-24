"""Nonsecret fixed IPC resources, payloads and durable write evidence."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_ipc import paired_ipc_pod
from ads_sandbox_manager.pair_objects import PROJECT, PairBinding, pair_labels
from ads_sandbox_manager.session_objects import ipc_name, ipc_pvc

IPC_ROLES = ("volume", "pod")


def ipc_role(role: str) -> None:
    if role not in IPC_ROLES:
        raise ValueError("unsupported paired IPC resource")


def new_ipc_resources() -> dict[str, Any]:
    return {role: {"payload": None, "uid": None, "dispatch": "unissued"} for role in IPC_ROLES}


def ipc_identity(settings: Settings, pair: PairBinding, role: str) -> Object:
    ipc_role(role)
    if role == "volume":
        result = ipc_pvc(settings, pair.session_id, pair.sandbox_id, settings.golden_version)
        result["metadata"]["labels"][PROJECT] = str(pair.project_id)
        return {key: value for key, value in result.items() if key != "spec"}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": ipc_name(pair.sandbox_id),
            "namespace": settings.namespace,
            "labels": pair_labels(settings, pair, "ipc"),
        },
    }


def validate_ipc_payload(role: str, value: object) -> None:
    ipc_role(role)
    fields = {
        "manifest",
        "control_uids",
        "compute_uids",
        "relay_input_uids",
        "custody_uid",
        "state_id",
    }
    if role == "pod":
        fields |= {"volume_uid", "ads_service_subject"}
    try:
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or not isinstance(value["manifest"], dict)
        ):
            raise ValueError
        for field, count in (("control_uids", 8), ("compute_uids", 4), ("relay_input_uids", 2)):
            values = value[field]
            if (
                not isinstance(values, dict)
                or len(values) != count
                or not all(
                    isinstance(key, str) and isinstance(uid, str) and uid.strip()
                    for key, uid in values.items()
                )
            ):
                raise ValueError
        for field in ("custody_uid", *(("volume_uid",) if role == "pod" else ())):
            if not isinstance(value[field], str) or not value[field].strip():
                raise ValueError
        for field in ("state_id", *(("ads_service_subject",) if role == "pod" else ())):
            if not isinstance(value[field], str) or str(UUID(value[field])) != value[field]:
                raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise RuntimeError("corrupt paired IPC payload") from None


def validate_ipc_resources(value: object) -> None:
    if not isinstance(value, dict) or set(value) != set(IPC_ROLES):
        raise RuntimeError("corrupt paired IPC resources")
    for role, entry in value.items():
        if not isinstance(entry, dict) or set(entry) != {"payload", "uid", "dispatch"}:
            raise RuntimeError("corrupt paired IPC resource")
        if entry["dispatch"] == "unissued":
            if entry != new_ipc_resources()[role]:
                raise RuntimeError("corrupt unissued paired IPC resource")
            continue
        if entry["dispatch"] not in ("inflight", "settled") or (
            entry["uid"] is not None
            and (not isinstance(entry["uid"], str) or not entry["uid"].strip())
        ):
            raise RuntimeError("corrupt paired IPC dispatch")
        validate_ipc_payload(role, entry["payload"])


def ipc_manifest(settings: Settings, pair: PairBinding, role: str, payload: Object) -> Object:
    ipc_role(role)
    if role == "volume":
        desired = {
            **ipc_pvc(settings, pair.session_id, pair.sandbox_id, settings.golden_version),
            **ipc_identity(settings, pair, role),
        }
    else:
        desired = paired_ipc_pod(
            settings,
            pair,
            payload["compute_uids"]["Pod/guest"],
            UUID(payload["ads_service_subject"]),
        )
    if "manifest" in payload:
        validate_ipc_payload(role, payload)
        if desired != payload["manifest"]:
            raise RuntimeError("committed paired IPC manifest changed")
    return desired
