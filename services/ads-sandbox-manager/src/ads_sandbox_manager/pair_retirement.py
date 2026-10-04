"""Plain-column retirement evidence: kube absence plus the retired_at fence."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_sandbox_manager.store import Base

from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession, SessionPVC, advance

RETIREMENT_KINDS = ("idle", "service", "reap", "orphan", "orphan-retained", "recovery")


def retirement_kind(work: CleanupWork, intent: PairIntent) -> str:
    """Derive the retirement kind from the authorized claim and plain columns."""
    retained = work.kind == "idle" or any(item.get("retain") for item in work.targets)
    if work.kind == "orphan":
        return "orphan-retained" if retained else "orphan"
    return work.kind


def retention(kind: str) -> bool:
    """Retained lifetimes keep their original workspace storage."""
    if kind not in RETIREMENT_KINDS:
        raise ValueError("unsupported retirement kind")
    return kind in ("idle", "orphan-retained")


class PairRetirementRepository:
    """Caller commits atomically with its lifecycle transition; no external I/O.

    O2: no PairRetirement rows are written. `PairIntent.retired_at` plus the
    permanent creator fence is the durable retirement record; teardown truth
    is kube API absence, observed per target by the cleanup adapter.
    """

    def __init__(self, lifecycle: LifecycleRepository) -> None:
        self.lifecycle = lifecycle

    async def require_destroyed_history(self, db: AsyncSession, row: SandboxSession) -> None:
        """Explicit fresh paired admission, never the legacy adoption path."""
        from ads_sandbox_manager.egress_state_store import EgressState

        generations = list(
            await db.scalars(
                select(PairIntent)
                .where(PairIntent.session_id == row.session_id)
                .order_by(PairIntent.claim_changed)
                .with_for_update()
            )
        )
        state_ids = set()
        for intent in generations:
            if intent.retired_at is None or intent.sandbox_id == row.sandbox_id:
                raise PairClaimLost("fresh admission precedes original generation retirement")
            await self.verify(db, intent.generation)
            if intent.egress_state_id is not None:
                state_ids.add(intent.egress_state_id)
        states = set(
            await db.scalars(
                select(EgressState.state_id).where(EgressState.session_id == row.session_id)
            )
        )
        if states != state_ids:
            raise PairClaimLost("fresh admission has untracked persistent ownership")
        if (
            row.ipc_pod_uid is not None
            or row.pvc_id is not None
            or await db.scalar(
                select(SessionPVC.pvc_id).where(SessionPVC.session_id == row.session_id).limit(1)
            )
            is not None
        ):
            raise PairClaimLost("fresh admission has unfinished session bindings")

    async def finish_idle(self, db: AsyncSession, expected: CleanupWork, now: datetime) -> bool:
        if expected.kind != "idle" or expected.session_id is None or expected.pvc_id is None:
            raise PairClaimLost("idle retirement claim required")
        if not await self.retire(db, expected, now):
            return False
        row = await db.get(SandboxSession, expected.session_id, with_for_update=True)
        pvc = await db.get(SessionPVC, expected.pvc_id, with_for_update=True)
        if row is None or pvc is None:
            raise PairClaimLost("idle retirement lifetime missing")
        retained = next((obj for obj in expected.targets if obj.get("retain")), None)
        if retained is None or retained.get("uid") != pvc.uid:
            raise PairClaimLost("idle retirement workspace proof changed")
        row.status = "stopped"
        row.status_changed_at = advance(row.status_changed_at, now)
        row.service_deadline = None
        row.claimed_by = None
        row.guest_deployment_uid = row.ipc_deployment_uid = row.ipc_pvc_uid = None
        row.ipc_pod_uid = None
        row.ca_attempt = row.ca_sources = row.ca_clones = None
        pvc.state = "detached"
        pvc.last_state_change = advance(pvc.last_state_change, now)
        pvc.release_evidence = dict(retained)
        stored = await db.get(CleanupWork, expected.work_id)
        assert stored is not None
        await db.delete(stored)
        await db.flush()
        return True

    async def finish_destroyed(self, db: AsyncSession, work: CleanupWork, now: datetime) -> bool:
        if work.kind not in ("orphan", "service", "reap"):
            raise PairClaimLost("destructive completion requires a destructive claim")
        if not await self.retire(db, work, now):
            return False
        if work.session_id is not None:
            row, pvc = await self.lifecycle.locked(db, work.session_id, work.sandbox_id)
            if row is None:
                raise PairClaimLost("destructive completion lacks original lifetime")
            if pvc is not None:
                retained = next(
                    (obj for obj in work.targets if obj.get("retain") and obj["name"] == pvc.name),
                    None,
                )
                if retained is not None:
                    raise PairClaimLost("destructive completion deletes retained workspace")
                await db.delete(pvc)
            row.pvc_id = row.pvc_uid = None
            row.guest_deployment_uid = row.ipc_deployment_uid = row.ipc_pvc_uid = None
            row.ipc_pod_uid = None
            row.ca_attempt = row.ca_sources = row.ca_clones = None
            row.claimed_by = row.service_deadline = None
            row.status = "stopped"
            # Destruction ends the stable identity; a later request starts a new sandbox.
            row.sandbox_id = uuid4()
            row.status_changed_at = advance(row.status_changed_at, now)
        stored = await db.get(CleanupWork, work.work_id)
        assert stored is not None
        await db.delete(stored)
        await db.flush()
        return True

    async def verify(self, db: AsyncSession, generation: UUID) -> dict[str, Any]:
        """Retirement state derived only from the intent's own plain columns.

        Returns the live intent; callers needing a kind derive it via
        retirement_kind from the original authorized work or retention().
        """
        intent = await db.get(PairIntent, generation, with_for_update=True, populate_existing=True)
        if (
            intent is None
            or intent.retired_at is None
            or not intent.creation_fenced
            or intent.cleanup_journal is not None
        ):
            raise PairClaimLost("retirement tombstone or original ownership changed")
        # Reconstruct the live immutable creator snapshot; runs all validators.
        await self.lifecycle.pair_snapshot(
            db, intent.session_id, intent.sandbox_id, generation=generation
        )
        return {
            "generation": intent.generation,
            "session_id": intent.session_id,
            "sandbox_id": intent.sandbox_id,
            "project_id": intent.project_id,
            "retired_at": intent.retired_at,
            "retained": intent.volume_resources["workspace"]["dispatch"] == "unissued",
        }

    async def retire(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        """Idempotent creator-fenced retirement; sets only intent.retired_at."""
        work = await self.lifecycle.owned_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        )
        pair = self.lifecycle.cleanup_pair(work)
        intent = await db.get(
            PairIntent, pair.generation, with_for_update=True, populate_existing=True
        )
        if intent is None:
            raise PairClaimLost("retirement original intent missing")
        if intent.retired_at is not None:
            return True
        if not await self.lifecycle.pair_writers_settled(
            db, work, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        if now.tzinfo is None:
            raise ValueError("retirement timestamp must be timezone-aware")
        intent.retired_at = now
        await db.flush()
        return True


class PairRetirement(Base):  # noqa: F811
    """Legacy table kept mapped; O2 writes no rows (no migration)."""

    __tablename__ = "sandbox_pair_retirement"

    generation: Mapped[UUID] = mapped_column(primary_key=True)
    session_id: Mapped[UUID] = mapped_column(index=True)
    sandbox_id: Mapped[UUID] = mapped_column(index=True)
    project_id: Mapped[UUID]
    work_id: Mapped[UUID]
    kind: Mapped[str]
    retired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    journal: Mapped[dict[str, Any]] = mapped_column(JSONB)
    journal_sha256: Mapped[str]
