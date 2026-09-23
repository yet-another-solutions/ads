"""Durable nonsecret inputs for trusted fixed-Pod constructors."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.pair_compute import (
    PrivateGuestRuntime,
    RelayRuntime,
    private_guest_pod,
    relay_pod,
)
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.store import SandboxSession

PUBLISHED_COMPUTE_ROLES = ("guest", "guest-relay", "egress-relay")


def new_compute_payloads() -> dict[str, Any]:
    return {role: None for role in ("guest", "egress", "guest-relay", "egress-relay")}


def guest_payload(row: SandboxSession, runtime: PrivateGuestRuntime) -> dict[str, Any]:
    if (
        row.pvc_id is None
        or not row.pvc_uid
        or row.ca_attempt is None
        or set(row.ca_clones or {}) != {"guest", "egress", "key"}
        or not all((row.ca_clones or {}).values())
        or not (row.ca_sources or {}).get("public")
    ):
        raise ValueError("exact guest volume identities are required")
    assert row.ca_clones is not None and row.ca_sources is not None
    return {
        "pvc_id": str(row.pvc_id),
        "pvc_uid": row.pvc_uid,
        "ca_attempt": str(row.ca_attempt),
        "ca_guest_uid": row.ca_clones["guest"],
        "ca_source_uid": row.ca_sources["public"],
        "golden_version": row.golden_version,
        "runtime": asdict(runtime),
    }


def relay_payload(runtime: RelayRuntime) -> dict[str, Any]:
    return {"runtime": asdict(runtime)}


def validate_payload(role: str, payload: object) -> None:
    if not isinstance(payload, dict):
        raise RuntimeError("corrupt pair compute payload")
    try:
        if role == "guest":
            if set(payload) != {
                "pvc_id",
                "pvc_uid",
                "ca_attempt",
                "ca_guest_uid",
                "ca_source_uid",
                "golden_version",
                "runtime",
                "manifest",
                "control_uids",
            }:
                raise ValueError
            for key in ("pvc_uid", "ca_guest_uid", "ca_source_uid", "golden_version"):
                if not isinstance(payload[key], str) or not payload[key].strip():
                    raise ValueError
            for key in ("pvc_id", "ca_attempt"):
                if str(UUID(payload[key])) != payload[key]:
                    raise ValueError
            PrivateGuestRuntime(**payload["runtime"])
        elif role in ("guest-relay", "egress-relay"):
            if set(payload) != {"runtime", "manifest", "control_uids"}:
                raise ValueError
            RelayRuntime(**payload["runtime"])
        else:
            raise ValueError
        if not isinstance(payload["manifest"], dict):
            raise ValueError
        controls = payload["control_uids"]
        if (
            not isinstance(controls, dict)
            or len(controls) != 8
            or not all(
                isinstance(key, str) and isinstance(uid, str) and uid.strip()
                for key, uid in controls.items()
            )
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise RuntimeError("corrupt pair compute payload") from None


def compute_manifest(
    settings: Settings,
    pair: PairBinding,
    role: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if role == "guest":
        desired = private_guest_pod(
            settings,
            pair,
            UUID(payload["pvc_id"]),
            UUID(payload["ca_attempt"]),
            PrivateGuestRuntime(**payload["runtime"]),
        )
    elif role in ("guest-relay", "egress-relay"):
        desired = relay_pod(settings, pair, role, RelayRuntime(**payload["runtime"]))
    else:
        raise ValueError("compute role has no published constructor")
    if "manifest" in payload:
        validate_payload(role, payload)
        if desired != payload["manifest"]:
            raise RuntimeError("committed pair compute manifest changed")
    return desired


def validate_compute_payloads(value: object) -> None:
    if not isinstance(value, dict) or set(value) != set(new_compute_payloads()):
        raise RuntimeError("corrupt pair compute payloads")
    if value["egress"] is not None:
        raise RuntimeError("egress compute constructor is not implemented")
    for role in PUBLISHED_COMPUTE_ROLES:
        if value[role] is not None:
            validate_payload(role, value[role])
