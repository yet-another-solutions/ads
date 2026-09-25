"""Proof-checked, non-cascading terminal attachment-generation evidence."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_resource_proof import (
    resource_targets,
    runtime_complete,
    storage_complete,
)
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import Base, SandboxSession, SessionPVC, advance


def digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def terminal(journal: dict[str, Any]) -> bool:
    """Only after the full retained-journal validator and original writer seal."""
    if journal["retain_workspace"]:
        state = journal["snapshot"]["egress_state"]
        if (
            state is None
            or state["volume_dispatch"] != "settled"
            or state["key_dispatch"] != "settled"
            or not state["volume_uid"]
            or not state["key_uid"]
            or journal["snapshot"]["volume_resources"]["workspace"]["dispatch"] != "settled"
            or not journal["snapshot"]["volume_resources"]["workspace"]["uid"]
            or journal["topic_disposition"] != "retained"
        ):
            return False
    return (
        runtime_complete(journal)
        and storage_complete(journal)
        and journal["resource_disposition"] == resource_targets(journal)
        and journal["topic_disposition"] is not None
    )


class PairRetirement(Base):
    """No cascade and no mutation API; retains the entire nonsecret proof."""

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


class PairRetirementRepository:
    """Caller commits atomically with its lifecycle transition; no external I/O."""

    def __init__(self, lifecycle: LifecycleRepository) -> None:
        self.lifecycle = lifecycle

    async def require_destroyed_history(self, db: AsyncSession, row: SandboxSession) -> None:
        """Explicit fresh paired admission, never the legacy adoption path."""
        from ads_sandbox_manager.egress_state_store import EgressState
        from ads_sandbox_manager.pair_disposal import PairDisposalRepository
        from ads_sandbox_manager.pair_transfer import PairTransferRepository

        generations = list(
            await db.scalars(
                select(PairIntent)
                .where(PairIntent.session_id == row.session_id)
                .order_by(PairIntent.claim_changed)
                .with_for_update()
            )
        )
        latest: dict[UUID, PairRetirement] = {}
        state_ids = set()
        for intent in generations:
            if intent.retired_at is None or intent.sandbox_id == row.sandbox_id:
                raise PairClaimLost("fresh admission precedes original generation retirement")
            saved = await self.verify(db, intent.generation)
            await PairTransferRepository(self.lifecycle).verify(db, intent)
            latest[intent.sandbox_id] = saved
            if intent.egress_state_id is not None:
                state_ids.add(intent.egress_state_id)
        states = set(
            await db.scalars(
                select(EgressState.state_id).where(EgressState.session_id == row.session_id)
            )
        )
        if states != state_ids:
            raise PairClaimLost("fresh admission has untracked persistent ownership")
        for saved in latest.values():
            if saved.kind in ("idle", "orphan-retained"):
                receipt = await PairDisposalRepository(self.lifecycle).verify(db, saved.generation)
                if receipt.completed_at is None:
                    raise PairClaimLost("fresh admission precedes retained storage destruction")
        if (
            row.ipc_pod_uid is not None
            or row.pvc_id is not None
            or await db.scalar(
                select(SessionPVC.pvc_id).where(SessionPVC.session_id == row.session_id).limit(1)
            )
            is not None
        ):
            raise PairClaimLost("fresh admission has unfinished session bindings")

    @staticmethod
    def owns_destroyed_pvc(saved: PairRetirement, pvc: SessionPVC) -> bool:
        """Terminal journal validates actual disposition, not just matching names."""
        original = saved.journal["snapshot"]["volume_resources"]["workspace"]
        if (pvc.session_id, pvc.sandbox_id) != (saved.session_id, saved.sandbox_id):
            return False
        if original["dispatch"] == "unissued":
            return pvc.uid is None
        return (
            not saved.journal["retain_workspace"]
            and original["uid"] == pvc.uid
            and original["payload"]["pvc_id"] == str(pvc.pvc_id)
            and terminal(saved.journal)
        )

    async def finish_destroyed(self, db: AsyncSession, work: CleanupWork, now: datetime) -> bool:
        if work.kind not in ("orphan", "service", "reap"):
            raise PairClaimLost("destructive completion requires a destructive claim")
        saved = await self.retire(db, work, now)
        if saved is None:
            return False
        if saved.kind == "orphan-retained":
            from ads_sandbox_manager.pair_disposal import PairDisposalRepository

            # Retention proof remains immutable. Orphan destruction is a new,
            # exclusive disposition of that retired lifetime, not a rewrite.
            await PairDisposalRepository(self.lifecycle).begin(db, work, saved, now)
            return False
        if work.session_id is not None:
            row, pvc = await self.lifecycle.locked(db, work.session_id, work.sandbox_id)
            if row is None or (pvc is not None and not self.owns_destroyed_pvc(saved, pvc)):
                raise PairClaimLost("destructive completion lacks original workspace disposition")
            if pvc is not None:
                await db.delete(pvc)
            row.pvc_id = row.pvc_uid = None
            row.guest_deployment_uid = row.ipc_deployment_uid = row.ipc_pvc_uid = None
            row.ipc_pod_uid = None
            row.ca_attempt = row.ca_sources = row.ca_clones = None
            row.claimed_by = row.service_deadline = None
            row.status = "stopped"
            row.sandbox_id = uuid4()
            row.status_changed_at = advance(row.status_changed_at, now)
        stored = await db.get(CleanupWork, work.work_id)
        assert stored is not None
        await db.delete(stored)
        await db.flush()
        return True

    async def finish_idle(self, db: AsyncSession, expected: CleanupWork, now: datetime) -> bool:
        if expected.kind != "idle" or expected.session_id is None or expected.pvc_id is None:
            raise PairClaimLost("idle retirement claim required")
        saved = await self.retire(db, expected, now)
        if saved is None:
            return False
        row = await db.get(SandboxSession, expected.session_id, with_for_update=True)
        pvc = await db.get(SessionPVC, expected.pvc_id, with_for_update=True)
        if row is None or pvc is None:
            raise PairClaimLost("idle retirement lifetime missing")
        captured = (
            saved.journal["storage_capture"].get("workspace")
            or saved.journal["partial_storage"].get("workspace")
            or saved.journal["unused_storage"].get("workspace", {}).get("capture", {}).get("target")
        )
        if captured is None or captured["uid"] != pvc.uid or not captured["retain"]:
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
        pvc.release_evidence = deepcopy(captured)
        stored = await db.get(CleanupWork, expected.work_id)
        assert stored is not None
        await db.delete(stored)
        await db.flush()
        return True

    async def verify(self, db: AsyncSession, generation: UUID) -> PairRetirement:
        intent = await db.get(PairIntent, generation, with_for_update=True, populate_existing=True)
        saved = await db.get(
            PairRetirement, generation, with_for_update=True, populate_existing=True
        )
        if (
            intent is None
            or saved is None
            or intent.retired_at is None
            or intent.retired_at != saved.retired_at
            or not intent.creation_fenced
            or (intent.session_id, intent.sandbox_id, intent.project_id)
            != (saved.session_id, saved.sandbox_id, saved.project_id)
            or saved.kind
            not in ("idle", "service", "reap", "orphan", "orphan-retained", "recovery")
            or saved.journal != intent.cleanup_journal
            or digest(saved.journal) != saved.journal_sha256
            or saved.journal["retain_workspace"] != (saved.kind in ("idle", "orphan-retained"))
        ):
            raise PairClaimLost("retirement tombstone or original ownership changed")
        # Reconstruct from live immutable creator fields, not from a caller's
        # copy of the saved journal. This runs every typed proof validator.
        await self.lifecycle.pair_snapshot(
            db, intent.session_id, intent.sandbox_id, generation=generation
        )
        if not terminal(saved.journal):
            raise RuntimeError("retirement lacks terminal original proof")
        return saved

    async def retire(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> PairRetirement | None:
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
            saved = await self.verify(db, pair.generation)
            expected_kind = (
                "orphan-retained"
                if work.kind == "orphan" and saved.journal["retain_workspace"]
                else work.kind
            )
            if saved.work_id != work.work_id or saved.kind != expected_kind:
                raise PairClaimLost("retirement cleanup claim changed")
            return saved
        if not await self.lifecycle.seal_pair_cleanup(
            db, work, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return None
        await self.lifecycle.pair_snapshot(db, pair.session_id, pair.sandbox_id)
        journal = intent.cleanup_journal
        if journal is None or not terminal(journal):
            return None
        if journal["retain_workspace"] != (work.kind == "idle") and not (
            work.kind == "orphan" and journal["retain_workspace"]
        ):
            raise PairClaimLost("retirement disposition differs from authorized lifecycle")
        if now.tzinfo is None:
            raise ValueError("retirement timestamp must be timezone-aware")
        intent.retired_at = now
        saved = PairRetirement(
            generation=pair.generation,
            session_id=pair.session_id,
            sandbox_id=pair.sandbox_id,
            project_id=pair.project_id,
            work_id=work.work_id,
            kind="orphan-retained"
            if work.kind == "orphan" and journal["retain_workspace"]
            else work.kind,
            retired_at=now,
            journal=deepcopy(journal),
            journal_sha256=digest(journal),
        )
        db.add(saved)
        await db.flush()
        return saved
