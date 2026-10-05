"""Exclusive expiry of retired retained storage; kube absence is the only proof."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_retirement import PairRetirementRepository
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import Base, SandboxSession, SessionPVC, advance


class PairDisposal(Base):
    """One-way claim; a lost session/work cannot make this lifetime transferable."""

    __tablename__ = "sandbox_pair_disposal"

    generation: Mapped[UUID] = mapped_column(primary_key=True)
    work_id: Mapped[UUID] = mapped_column(unique=True)
    session_id: Mapped[UUID] = mapped_column(index=True)
    sandbox_id: Mapped[UUID]
    project_id: Mapped[UUID]
    pvc_id: Mapped[UUID]
    pvc_uid: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PairDisposalRepository:
    def __init__(self, lifecycle: LifecycleRepository) -> None:
        self.lifecycle = lifecycle
        self.retirements = PairRetirementRepository(lifecycle)

    async def _retained_workspace(self, db: AsyncSession, generation: UUID) -> PairIntent:
        """Retained disposal applies only to idle-retained, untransferred lifetimes."""
        intent = await db.get(PairIntent, generation, with_for_update=True, populate_existing=True)
        if (
            intent is None
            or intent.retired_at is None
            or not intent.creation_fenced
            or intent.cleanup_journal is not None
            or await db.scalar(
                select(PairIntent.generation).where(PairIntent.retained_from == generation)
            )
            is not None
        ):
            raise PairClaimLost("retained lifetime is not idle-retained original storage")
        if intent.volume_resources["workspace"]["dispatch"] == "unissued":
            raise PairClaimLost("retained lifetime never held its workspace storage")
        return intent

    async def orphan_scope(self, db: AsyncSession, intent: PairIntent) -> None:
        owner = await db.scalar(
            select(SandboxSession.session_id)
            .where(
                or_(
                    SandboxSession.session_id == intent.session_id,
                    SandboxSession.sandbox_id == intent.sandbox_id,
                )
            )
            .with_for_update()
        )
        pvc = await db.scalar(
            select(SessionPVC.pvc_id).where(SessionPVC.session_id == intent.session_id).limit(1)
        )
        recovery = await db.scalar(
            select(CleanupWork.work_id)
            .where(
                CleanupWork.kind == "recovery",
                or_(
                    CleanupWork.session_id == intent.session_id,
                    CleanupWork.sandbox_id == intent.sandbox_id,
                ),
            )
            .limit(1)
        )
        if owner is not None or pvc is not None or recovery is not None:
            raise PairClaimLost("retained orphan has a live ownership claim")

    async def begin(
        self, db: AsyncSession, work: CleanupWork, generation: UUID, now: datetime
    ) -> PairDisposal:
        """Open the exclusive whole-lifetime destruction claim."""
        intent = await self._retained_workspace(db, generation)
        if (
            work.kind not in ("reap", "orphan")
            or not await self.lifecycle.owns(db, work)
            or work.sandbox_id != intent.sandbox_id
        ):
            raise PairClaimLost("retained expiry claim changed")
        workspace = intent.volume_resources["workspace"]
        pvc_id = UUID(workspace["payload"]["pvc_id"])
        if work.kind == "orphan":
            if work.session_id is not None or work.pvc_id is not None:
                raise PairClaimLost("retained orphan work has a session binding")
            await self.orphan_scope(db, intent)
        else:
            pvc = await db.get(SessionPVC, work.pvc_id, with_for_update=True)
            if (
                work.session_id != intent.session_id
                or pvc is None
                or pvc.pvc_id != pvc_id
                or pvc.uid != workspace["uid"]
            ):
                raise PairClaimLost("retained expiry workspace changed")
        receipt = PairDisposal(
            generation=intent.generation,
            work_id=work.work_id,
            session_id=intent.session_id,
            sandbox_id=intent.sandbox_id,
            project_id=intent.project_id,
            pvc_id=pvc_id,
            pvc_uid=workspace["uid"],
            created_at=now,
        )
        db.add(receipt)
        await db.flush()
        return receipt

    async def verify(self, db: AsyncSession, generation: UUID) -> PairDisposal:
        """One-way claim consistency, derived from the plain columns."""
        intent = await self._retained_workspace(db, generation)
        receipt = await db.get(
            PairDisposal, generation, with_for_update=True, populate_existing=True
        )
        if (
            receipt is None
            or (receipt.session_id, receipt.sandbox_id, receipt.project_id)
            != (intent.session_id, intent.sandbox_id, intent.project_id)
            or receipt.pvc_uid != intent.volume_resources["workspace"]["uid"]
            or str(receipt.pvc_id) != intent.volume_resources["workspace"]["payload"]["pvc_id"]
            or receipt.created_at < (intent.retired_at or intent.claim_changed)
            or receipt.completed_at is not None
            and receipt.completed_at < receipt.created_at
        ):
            raise PairClaimLost("retained disposal ownership or proof changed")
        return receipt

    async def owned(self, db: AsyncSession, expected: CleanupWork) -> PairDisposal:
        if expected.session_id is None and expected.kind != "orphan":
            raise PairClaimLost("retained expiry requires a session claim")
        if not await self.lifecycle.owns(db, expected):
            raise PairClaimLost("retained expiry claim lost")
        receipt = await db.scalar(
            select(PairDisposal).where(PairDisposal.work_id == expected.work_id)
        )
        if receipt is None:
            raise PairClaimLost("retained expiry receipt missing")
        receipt = await self.verify(db, receipt.generation)
        if expected.kind == "orphan":
            await self._retained_workspace(db, receipt.generation)
            intent = await db.get(PairIntent, receipt.generation)
            if intent is None:
                raise PairClaimLost("orphan scope lacks its retained intent")
            await self.orphan_scope(db, intent)
        work = await db.get(CleanupWork, expected.work_id, populate_existing=True)
        if (
            work is None
            or receipt.completed_at is not None
            or work.kind not in ("reap", "orphan")
            or (work.session_id, work.sandbox_id, work.pvc_id, work.state_changed, work.pvc_changed)
            != (
                expected.session_id,
                expected.sandbox_id,
                expected.pvc_id,
                expected.state_changed,
                expected.pvc_changed,
            )
            or work.sandbox_id != receipt.sandbox_id
            or (
                work.kind == "reap"
                and (work.session_id, work.pvc_id) != (receipt.session_id, receipt.pvc_id)
            )
            or (work.kind == "orphan" and (work.session_id is not None or work.pvc_id is not None))
        ):
            raise PairClaimLost("retained expiry work identity changed")
        return receipt

    async def finish(self, db: AsyncSession, work: CleanupWork, now: datetime) -> bool:
        receipt = await self.owned(db, work)
        if work.kind != "orphan":
            row, pvc = await self.lifecycle.locked(db, receipt.session_id, receipt.sandbox_id)
            if row is None or pvc is None or pvc.uid != receipt.pvc_uid:
                raise PairClaimLost("retained expiry lifetime changed")
            row.pvc_id = row.pvc_uid = None
            # Destruction ends the stable identity; a later request starts a new sandbox.
            row.sandbox_id = uuid4()
            row.status_changed_at = advance(row.status_changed_at, now)
            await db.delete(pvc)
        receipt.completed_at = now
        stored = await db.get(CleanupWork, work.work_id)
        assert stored is not None
        await db.delete(stored)
        await db.flush()
        return True
