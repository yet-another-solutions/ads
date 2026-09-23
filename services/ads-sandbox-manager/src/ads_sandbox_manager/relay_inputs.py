"""Immutable relay inputs: durable public payload, private bytes only at the API."""

from __future__ import annotations

import base64
import json
from dataclasses import asdict
from typing import Any
from uuid import UUID

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_compute import RelayRuntime, relay_configuration, relay_input_name
from ads_sandbox_manager.pair_objects import PairBinding, metadata
from ads_sandbox_manager.relay_keys import RelayKeys, validate_public_keys

INPUT_ROLES = ("guest-relay", "egress-relay")


def input_role(role: str) -> str:
    if role not in INPUT_ROLES:
        raise ValueError("invalid relay input role")
    return role


def new_relay_inputs() -> dict[str, Any]:
    return {role: {"payload": None, "uid": None, "dispatch": "unissued"} for role in INPUT_ROLES}


def input_payload(
    pair: PairBinding,
    role: str,
    runtime: RelayRuntime,
    public_keys: dict[str, str],
    custody_uid: str,
    pod_uids: dict[str, str],
    service_uid: str,
    service_ipv4: str,
) -> Object:
    input_role(role)
    validate_public_keys(public_keys)
    if set(pod_uids) != set(INPUT_ROLES):
        raise ValueError("both recorded relay Pod identities are required")
    for uid in (*pod_uids.values(), custody_uid, service_uid):
        if not isinstance(uid, str) or not uid.strip():
            raise ValueError("recorded relay input dependency UID required")
    for uid in pod_uids.values():
        if str(UUID(uid)) != uid:
            raise ValueError("canonical relay Pod UID required")
    # Validate the numeric endpoint even for the listening egress relay.
    guest = relay_configuration(
        pair,
        "guest-relay",
        UUID(pod_uids["guest-relay"]),
        public_keys["egress"],
        runtime,
        service_ipv4,
    )
    config = (
        guest
        if role == "guest-relay"
        else relay_configuration(pair, role, UUID(pod_uids[role]), public_keys["guest"], runtime)
    )
    return {
        "runtime": asdict(runtime),
        "public_keys": dict(public_keys),
        "custody_uid": custody_uid,
        "pod_uids": dict(pod_uids),
        "service_uid": service_uid,
        "service_ipv4": service_ipv4,
        "configuration": config,
    }


def validate_payload(pair: PairBinding, role: str, payload: object) -> None:
    try:
        if not isinstance(payload, dict):
            raise ValueError
        expected = input_payload(
            pair,
            role,
            RelayRuntime(**payload["runtime"]),
            payload["public_keys"],
            payload["custody_uid"],
            payload["pod_uids"],
            payload["service_uid"],
            payload["service_ipv4"],
        )
        if payload != expected:
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise RuntimeError("corrupt relay input payload") from None


def validate_relay_inputs(pair: PairBinding, value: object) -> None:
    if not isinstance(value, dict) or set(value) != set(INPUT_ROLES):
        raise RuntimeError("corrupt relay input evidence")
    for role, entry in value.items():
        if not isinstance(entry, dict) or set(entry) != {"payload", "uid", "dispatch"}:
            raise RuntimeError("corrupt relay input evidence")
        if entry["dispatch"] == "unissued":
            if entry != new_relay_inputs()[role]:
                raise RuntimeError("corrupt relay input evidence")
            continue
        if entry["dispatch"] not in ("inflight", "settled") or (
            entry["uid"] is not None
            and (not isinstance(entry["uid"], str) or not entry["uid"].strip())
        ):
            raise RuntimeError("corrupt relay input evidence")
        validate_payload(pair, role, entry["payload"])


def input_identity(settings: Settings, pair: PairBinding, role: str) -> Object:
    meta = metadata(settings, pair, input_role(role))
    meta["name"] = relay_input_name(pair, role)
    meta["labels"]["ads.io/relay-input"] = role
    return {"apiVersion": "v1", "kind": "Secret", "metadata": meta}


def input_secret(
    settings: Settings, pair: PairBinding, role: str, payload: Object, keys: RelayKeys
) -> Object:
    validate_payload(pair, role, payload)
    if keys.public_keys() != payload["public_keys"]:
        raise ValueError("relay input keys do not match committed custody")
    config = json.dumps(payload["configuration"], sort_keys=True, separators=(",", ":")).encode()
    return {
        **input_identity(settings, pair, role),
        "type": "Opaque",
        "immutable": True,
        "data": {
            "config.json": base64.b64encode(config).decode(),
            "wg.key": keys.secret_data()[role.removesuffix("-relay") + ".key"],
        },
    }
