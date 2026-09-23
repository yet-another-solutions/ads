"""Committed nonsecret egress construction and exact SQL dependency checks."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.egress_compute import EgressRuntime, egress_pod
from ads_sandbox_manager.egress_state_store import (
    EgressState,
    require_cleanup_state,
    state_from_snapshot,
    state_snapshot,
)
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession


def runtime_from_payload(value: Any) -> EgressRuntime:
    if not isinstance(value, dict):
        raise ValueError("egress runtime must be an object")
    copied = dict(value)
    subject = copied["ipc_service_subject"]
    if not isinstance(subject, str) or str(UUID(subject)) != subject:
        raise ValueError("canonical IPC subject required")
    copied["ipc_service_subject"] = UUID(subject)
    return EgressRuntime(**copied)


def egress_payload(
    row: SandboxSession, state: EgressState, runtime: EgressRuntime
) -> dict[str, Any]:
    if (
        not isinstance(row.ca_attempt, UUID)
        or set(row.ca_clones or {}) != {"guest", "egress", "key"}
        or set(row.ca_sources or {}) != {"public", "private"}
        or not all(
            isinstance(uid, str) and uid.strip()
            for uid in [*(row.ca_clones or {}).values(), *(row.ca_sources or {}).values()]
        )
    ):
        raise ValueError("exact paired CA identities required")
    assert row.ca_clones is not None and row.ca_sources is not None
    encoded = asdict(runtime)
    encoded["ipc_service_subject"] = str(runtime.ipc_service_subject)
    return {
        "ca_attempt": str(row.ca_attempt),
        "ca_clones": {role: row.ca_clones[role] for role in ("egress", "key")},
        "ca_sources": dict(row.ca_sources),
        "golden_version": row.golden_version,
        "state": state_snapshot(state),
        "runtime": encoded,
    }


def validate_egress_payload(payload: dict[str, Any]) -> None:
    if set(payload) != {
        "ca_attempt",
        "ca_clones",
        "ca_sources",
        "golden_version",
        "state",
        "runtime",
        "manifest",
        "control_uids",
    }:
        raise ValueError("incomplete egress payload")
    if (
        not isinstance(payload["ca_attempt"], str)
        or str(UUID(payload["ca_attempt"])) != payload["ca_attempt"]
        or not isinstance(payload["golden_version"], str)
        or not payload["golden_version"].strip()
    ):
        raise ValueError("invalid egress CA identity")
    for key, roles in (("ca_clones", {"egress", "key"}), ("ca_sources", {"public", "private"})):
        values = payload[key]
        if (
            not isinstance(values, dict)
            or set(values) != roles
            or not all(isinstance(uid, str) and uid.strip() for uid in values.values())
        ):
            raise ValueError("invalid egress CA identities")
    state = state_from_snapshot(payload["state"])
    if (
        state.key_dispatch != "settled"
        or state.volume_dispatch != "settled"
        or state.key_uid is None
        or state.volume_uid is None
    ):
        raise ValueError("settled bound egress state required")
    runtime_from_payload(payload["runtime"])


def egress_manifest(
    settings: Settings, pair: PairBinding, payload: dict[str, Any]
) -> dict[str, Any]:
    return egress_pod(
        settings,
        pair,
        UUID(payload["ca_attempt"]),
        state_from_snapshot(payload["state"]),
        runtime_from_payload(payload["runtime"]),
    )


async def require_egress_dependencies(
    db: AsyncSession, intent: PairIntent, current: SandboxSession, payload: dict[str, Any]
) -> None:
    state = await db.scalar(
        select(EgressState)
        .where(EgressState.state_id == intent.egress_state_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if state is None:
        raise PairClaimLost("persistent egress compute reservation missing")
    require_cleanup_state(state, intent)
    expected = egress_payload(current, state, runtime_from_payload(payload["runtime"]))
    if any(payload[key] != value for key, value in expected.items()):
        raise PairClaimLost("egress compute dependency identity changed")
