"""Reconcile exact durable pair ownership, without discovering arbitrary Secrets."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import String, and_, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from ads_sandbox_manager.egress_state_store import EgressState
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository, target
from ads_sandbox_manager.pair_disposal import PairDisposal, PairDisposalRepository
from ads_sandbox_manager.pair_compute import relay_input_name
from ads_sandbox_manager.pair_objects import pair_name
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.pair_transfer import PairTransfer
from ads_sandbox_manager.session_objects import ca_consumer_name, ipc_name, session_name
from ads_sandbox_manager.store import SandboxSession, SessionPVC


class PairRegistry:
    """The non-cascading ledger is the inventory for every paired resource type.

    Exact control/Pod/PVC/Secret reads remain in PairCleanupCapture. Objects with
    only labels and no corresponding durable intent never gain paired deletion
    authority, including after a fresh-schema reset.
    """

    def __init__(self, lifecycle: LifecycleRepository) -> None:
        self.lifecycle = lifecycle
        self.disposal = PairDisposalRepository(lifecycle)

    async def candidates(
        self, db: AsyncSession, limit: int, *, after: UUID | None = None
    ) -> list[UUID]:
        owners = select(SandboxSession.session_id).where(
            SandboxSession.session_id == PairIntent.session_id
        )
        pending = select(PairDisposal.generation).where(
            PairDisposal.generation == PairIntent.generation,
            PairDisposal.completed_at.is_(None),
        )
        recoverable = owners.where(
            SandboxSession.status.in_(("shutting_down", "recovering", "service"))
        )
        # O2: retirement state derives from the intent's own plain columns.
        # No PairRetirement rows are written, so retained lifetimes must be
        # identified structurally: the retained workspace still holds its
        # original storage, or this generation inherits one.
        query = (
            select(PairIntent.generation)
            .where(
                or_(~owners.exists(), recoverable.exists(), pending.exists()),
                ~select(CleanupWork.work_id)
                .where(CleanupWork.sandbox_id == PairIntent.sandbox_id)
                .exists(),
                or_(
                    PairIntent.retired_at.is_(None),
                    and_(
                        PairIntent.retired_at.is_not(None),
                        or_(
                            and_(
                                PairIntent.volume_resources["workspace"]["dispatch"]
                                .cast(String)
                                != "unissued",
                                PairIntent.retained_from.is_(None),
                            ),
                            PairIntent.retained_from.is_not(None),
                        ),
                    ),
                ),
                ~select(PairTransfer.generation)
                .where(PairTransfer.predecessor == PairIntent.generation)
                .exists(),
                ~select(PairDisposal.generation)
                .where(
                    PairDisposal.generation == PairIntent.generation,
                    PairDisposal.completed_at.is_not(None),
                )
                .exists(),
            )
            .order_by(PairIntent.claim_changed, PairIntent.generation)
            .limit(limit)
        )
        cursor = await db.get(PairIntent, after) if after is not None else None
        if cursor is not None:
            page = list(
                await db.scalars(
                    query.where(
                        tuple_(PairIntent.claim_changed, PairIntent.generation)
                        > (cursor.claim_changed, cursor.generation)
                    )
                )
            )
            if page:
                return page
        return list(await db.scalars(query))

    async def reconcile(
        self, db: AsyncSession, generation: UUID, now: datetime, timeout: float
    ) -> CleanupWork | None:
        observed = await db.get(PairIntent, generation)
        if observed is None:
            return None
        row = await db.get(SandboxSession, observed.session_id, with_for_update=True)
        pvc = await db.scalar(
            select(SessionPVC)
            .where(
                SessionPVC.session_id == observed.session_id,
                SessionPVC.sandbox_id == observed.sandbox_id,
            )
            .with_for_update()
        )
        intent = await db.get(PairIntent, generation, with_for_update=True, populate_existing=True)
        if (
            intent is None
            or await db.scalar(
                select(CleanupWork.work_id)
                .where(CleanupWork.sandbox_id == intent.sandbox_id)
                .limit(1)
            )
            is not None
        ):
            return None
        if (
            await db.scalar(
                select(PairTransfer.generation).where(PairTransfer.predecessor == generation)
            )
            is not None
        ):
            return None
        if intent.retired_at is not None:
            # O2: retention is structural — a retired generation with its
            # original workspace storage still issued is idle-retained.
            retained = (
                intent.volume_resources["workspace"]["dispatch"] != "unissued"
                and intent.retained_from is None
            )
            if not retained:
                return None
            workspace = intent.volume_resources["workspace"]
            receipt = await db.get(PairDisposal, generation, with_for_update=True)
            if receipt is not None:
                receipt = await self.disposal.verify(db, generation)
                if receipt.completed_at is not None:
                    return None
            if row is None:
                await self.disposal.orphan_scope(db, intent)
                kind = "orphan"
            elif (
                receipt is not None
                and row.status == "stopped"
                and row.sandbox_id == intent.sandbox_id
                and row.project_id == intent.project_id
                and row.pvc_id == receipt.pvc_id
                and row.pvc_uid == receipt.pvc_uid
                and pvc is not None
                and pvc.state == "destroying"
            ):
                kind = "reap"
            else:
                return None
            # Retained expiry is destructive: the retired generation's captured
            # inventory is the exact teardown scope. Reconstruct it from the
            # intent's plain columns; the workspace PVC is the receipt's claim.
            binding = intent.binding()
            targets: list[dict[str, Any]] = [
                target("Pod", ipc_name(intent.sandbox_id), intent.ipc_resources["pod"]["uid"])
            ]
            for kind_role, uid in intent.compute_uids.items():
                if uid is not None:
                    role = kind_role.removeprefix("Pod/")
                    targets.append(target("Pod", pair_name(binding, role), uid))
            for key, uid in intent.control_uids.items():
                if uid is None:
                    continue
                ckind, crole = key.split("/", 1)
                # Every control builder names its object pair_name(binding, role).
                targets.append(target(ckind, pair_name(binding, crole), uid))
            targets.append(
                target(
                    "PersistentVolumeClaim",
                    ipc_name(intent.sandbox_id),
                    intent.ipc_resources["volume"]["uid"],
                )
            )
            for role in ("guest", "egress", "key"):
                entry = intent.volume_resources.get(role)
                if entry and entry.get("uid"):
                    targets.append(
                        target(
                            "PersistentVolumeClaim",
                            ca_consumer_name(intent.sandbox_id, role),
                            entry["uid"],
                        )
                    )
            for role, entry in intent.relay_inputs.items():
                if entry["uid"] is not None:
                    targets.append(
                        target("Secret", relay_input_name(binding, role), entry["uid"])
                    )
            if intent.egress_state_id is not None:
                state = await db.get(EgressState, intent.egress_state_id)
                if state is not None:
                    for role, uid_name in (("key", state.key_uid), ("volume", state.volume_uid)):
                        targets.append(
                            target(
                                "Secret" if role == "key" else "PersistentVolumeClaim",
                                f"ads-egress-{role}-{state.state_id}",
                                uid_name,
                            )
                        )
            targets.append(
                target(
                    "PersistentVolumeClaim",
                    session_name(pvc.pvc_id) if pvc else session_name(UUID(workspace["payload"]["pvc_id"])),
                    workspace["uid"],
                )
            )
            # Relay custody Secret: retired-generation ownership is part of the
            # whole-lifetime teardown scope.
            custody = intent.relay_custody
            if custody.get("uid"):
                targets.append(
                    target(
                        "Secret",
                        f"ads-relay-keys-{intent.sandbox_id}.{intent.generation}",
                        custody["uid"],
                    )
                )

            work = CleanupWork(
                work_id=receipt.work_id if receipt else uuid4(),
                session_id=row.session_id if row else None,
                sandbox_id=intent.sandbox_id,
                pvc_id=pvc.pvc_id if row and pvc else None,
                kind=kind,
                state_changed=row.status_changed_at if row else now,
                pvc_changed=pvc.last_state_change if row and pvc else None,
                deadline=now + timedelta(seconds=timeout),
                acknowledged=True,
                targets=targets,
                pair_snapshot=None,
            )
            db.add(work)
            await db.flush()
            # Reconstructed creator snapshot: release() fences every deletion
            # against the retired generation's captured ownership, exactly like
            # a retained-expiry reap built by repository.reap(). Orphan work
            # (session row deleted) intentionally stays snapshot-less; each
            # object is independently revalidated before deletion.
            if kind != "orphan":
                work.pair_snapshot = await self.lifecycle.pair_snapshot(
                    db, intent.session_id, intent.sandbox_id, generation=intent.generation
                )
            if receipt is None:
                await self.disposal.begin(db, work, intent.generation, now)
            return work
        snapshot = await self.lifecycle.pair_snapshot(
            db, intent.session_id, intent.sandbox_id, generation=generation
        )
        if snapshot is None:
            raise PairClaimLost("durable pair inventory lost its original snapshot")
        if row is None:
            if pvc is not None:
                return None
            kind = "orphan"
        elif row.project_id != intent.project_id:
            raise PairClaimLost("durable pair inventory acquired a foreign project")
        elif row.status == "recovering" and (pvc is None or pvc.state == "failed"):
            kind = "recovery"
        elif row.sandbox_id == intent.sandbox_id and row.pvc_id == (pvc.pvc_id if pvc else None):
            if row.status == "shutting_down" and pvc is not None and pvc.state == "detaching":
                kind = "idle"
            elif row.status == "service" and (pvc is None or pvc.state == "detached"):
                kind = "service"
            else:
                return None
        else:
            return None
        # O2: no sealed journal. Work targets come from the live session/PVC
        # binding; a retained (idle) reconciliation carries the workspace target
        # with retain=True. Non-idle kinds never re-drain.
        targets = (
            [
                target(
                    "PersistentVolumeClaim",
                    session_name(pvc.pvc_id),
                    pvc.uid,
                    retain=kind == "idle",
                )
            ]
            if pvc
            else []
        )
        work = CleanupWork(
            work_id=uuid4(),
            session_id=row.session_id if row else None,
            sandbox_id=intent.sandbox_id,
            pvc_id=pvc.pvc_id if row and pvc else None,
            kind=kind,
            state_changed=row.status_changed_at if row else now,
            pvc_changed=pvc.last_state_change if row and pvc else None,
            deadline=now + timedelta(seconds=timeout),
            # Idle requires the drain ack before teardown; every other kind is
            # already destructive or observation-only.
            acknowledged=kind != "idle",
            targets=targets,
            pair_snapshot=snapshot,
        )
        db.add(work)
        await db.flush()
        if kind == "orphan":
            # Shared original-creator fencing rules still check all independent
            # session/PVC/recovery ownership, not just the lookup above.
            await self.lifecycle.owned_pair_cleanup(db, work, now)
        return work
