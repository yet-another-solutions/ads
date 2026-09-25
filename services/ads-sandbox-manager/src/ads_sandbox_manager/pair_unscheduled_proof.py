"""Retained original unscheduled-Pod deletion evidence, not node inventory."""

from __future__ import annotations

from datetime import datetime

from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES

RUNTIME_ROLES = ("ipc", *COMPUTE_ROLES)


def pod_uid(snapshot: Object, role: str) -> str | None:
    if role not in RUNTIME_ROLES:
        raise ValueError("unsupported original runtime role")
    value = (
        snapshot["ipc_resources"]["pod"]["uid"]
        if role == "ipc"
        else snapshot["compute_uids"][f"Pod/{role}"]
    )
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError("invalid original runtime Pod UID")
    return value


def validate_observation(value: Object, uid: str | None) -> None:
    try:
        if (
            not isinstance(value, dict)
            or set(value) != {"uid", "resource_version", "node", "deletion_timestamp"}
            or not isinstance(uid, str)
            or not uid.strip()
            or value["uid"] != uid
            or type(value["node"]) is not str
            or value["node"] != ""
            or not isinstance(value["resource_version"], str)
            or not value["resource_version"].strip()
        ):
            raise ValueError
        deleted = value["deletion_timestamp"]
        if deleted is not None and (
            not isinstance(deleted, str) or datetime.fromisoformat(deleted).tzinfo is None
        ):
            raise ValueError
    except (TypeError, ValueError, KeyError):
        raise RuntimeError("invalid original unscheduled Pod observation") from None


def validate_unscheduled(snapshot: Object, entries: Object) -> None:
    if not isinstance(entries, dict) or not set(entries) <= set(RUNTIME_ROLES):
        raise RuntimeError("invalid retained unscheduled role inventory")
    for role, attempts in entries.items():
        if not isinstance(attempts, list) or not 1 <= len(attempts) <= 128:
            raise RuntimeError("invalid retained unscheduled dispatch history")
        uid = pod_uid(snapshot, role)
        for index, attempt in enumerate(attempts):
            if (
                not isinstance(attempt, dict)
                or set(attempt) != {"capture", "dispatch", "response"}
                or attempt["dispatch"] not in ("inflight", "conflict", "settled", "observed")
                or (index < len(attempts) - 1 and attempt["dispatch"] != "conflict")
            ):
                raise RuntimeError("invalid original unscheduled dispatch")
            validate_observation(attempt["capture"], uid)
            if attempt["dispatch"] == "observed":
                if (
                    attempt["capture"]["deletion_timestamp"] is None
                    or attempt["response"] is not None
                ):
                    raise RuntimeError("positive unscheduled deletion observation required")
            else:
                if attempt["capture"]["deletion_timestamp"] is not None:
                    raise RuntimeError("unscheduled DELETE requires non-deleting capture")
                if attempt["dispatch"] == "settled":
                    validate_observation(attempt["response"], uid)
                elif attempt["response"] is not None:
                    raise RuntimeError("unsettled DELETE cannot manufacture a response")


def never_scheduled(journal: Object, role: str) -> bool:
    attempts = journal["unscheduled"].get(role, [])
    return bool(attempts and attempts[-1]["dispatch"] in ("observed", "settled"))
