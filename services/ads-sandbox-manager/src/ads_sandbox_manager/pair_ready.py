"""SQL admission after authenticated IPC readiness, never a health substitute."""

from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ads_sandbox_manager.egress_state_store import EgressState
from ads_sandbox_manager.pair_ipc_store import PairIpcRepository
from ads_sandbox_manager.pair_store import PairIntent, PairIntentRepository
from ads_sandbox_manager.pair_volume_store import PairVolumeRepository
from ads_sandbox_manager.store import SandboxSession


async def paired_ready(db: AsyncSession, row: SandboxSession) -> bool | None:
    """None identifies a truly unpaired fixture/legacy row; incomplete is False."""
    intent = await db.scalar(
        select(PairIntent)
        .where(
            or_(
                PairIntent.session_id == row.session_id,
                PairIntent.sandbox_id == row.sandbox_id,
            )
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if intent is None:
        retained = await db.scalar(
            select(EgressState.state_id)
            .where(
                or_(
                    EgressState.session_id == row.session_id,
                    EgressState.sandbox_id == row.sandbox_id,
                )
            )
            .limit(1)
        )
        return None if retained is None else False
    if (
        row.status != "creating"
        or row.claimed_by is None
        or row.guest_deployment_uid is not None
        or row.ipc_deployment_uid is not None
    ):
        return False
    try:
        pairs = PairIntentRepository()
        intent = await pairs.owned(db, row, row.claimed_by, intent.generation)
        if intent.topics_dispatch != "settled":
            return False
        for resources in (intent.volume_resources, intent.ipc_resources):
            if any(
                entry["dispatch"] != "settled" or not entry["uid"] for entry in resources.values()
            ):
                return False
        for role, entry in intent.volume_resources.items():
            await PairVolumeRepository(pairs)._current(
                db, row, row.claimed_by, intent.generation, role, entry["payload"]
            )
            uid = row.pvc_uid if role == "workspace" else (row.ca_clones or {}).get(role)
            if uid != entry["uid"]:
                return False
        ipc = PairIpcRepository(pairs)
        for role, entry in intent.ipc_resources.items():
            await ipc._dependencies(db, intent, row, role, entry["payload"])
            uid = row.ipc_pvc_uid if role == "volume" else row.ipc_pod_uid
            if uid != entry["uid"]:
                return False
    except (RuntimeError, ValueError, KeyError, TypeError):
        return False
    return True
