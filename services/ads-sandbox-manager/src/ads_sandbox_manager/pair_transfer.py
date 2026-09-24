"""Exclusive retained-resource ownership transfer after proven idle retirement."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, UniqueConstraint, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_sandbox_manager.egress_state_store import EgressState, state_snapshot
from ads_sandbox_manager.lifecycle_store import LifecycleRepository
from ads_sandbox_manager.pair_retirement import PairRetirement, PairRetirementRepository
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.store import Base, SandboxSession, SessionPVC


class PairTransfer(Base):
    """Immutable one-use transfer receipt, independent of session/work cascades."""

    __tablename__ = "sandbox_pair_transfer"
    __table_args__ = (UniqueConstraint("predecessor", name="sandbox_pair_transfer_once"),)

    generation: Mapped[UUID] = mapped_column(primary_key=True)
    predecessor: Mapped[UUID]
    session_id: Mapped[UUID] = mapped_column(index=True)
    sandbox_id: Mapped[UUID] = mapped_column(index=True)
    project_id: Mapped[UUID]
    claim_owner: Mapped[UUID]
    claim_changed: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    retirement_sha256: Mapped[str]
    state: Mapped[dict[str, Any]] = mapped_column(JSONB)
    workspace: Mapped[dict[str, Any]] = mapped_column(JSONB)


class PairTransferRepository:
    def __init__(self, lifecycle: LifecycleRepository) -> None:
        self.lifecycle = lifecycle
        self.retirements = PairRetirementRepository(lifecycle)

    async def available(
        self, db: AsyncSession, row: SandboxSession
    ) -> tuple[PairRetirement, EgressState, SessionPVC]:
        """Called under the session lock before claim or generation allocation."""
        prior = await db.scalar(
            select(PairIntent)
            .where(PairIntent.sandbox_id == row.sandbox_id)
            .order_by(PairIntent.claim_changed.desc())
            .limit(1)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if prior is None or prior.retired_at is None:
            raise PairClaimLost("retained sandbox has no retired original generation")
        saved = await self.retirements.verify(db, prior.generation)
        if (
            saved.kind != "idle"
            or (saved.session_id, saved.sandbox_id, saved.project_id)
            != (row.session_id, row.sandbox_id, row.project_id)
            or await db.scalar(
                select(PairTransfer.generation).where(PairTransfer.predecessor == prior.generation)
            )
            is not None
        ):
            raise PairClaimLost("retained generation is not available for exclusive transfer")
        old = saved.journal["snapshot"]["volume_resources"]["workspace"]
        pvc = (
            await db.get(SessionPVC, row.pvc_id, with_for_update=True, populate_existing=True)
            if row.pvc_id is not None
            else None
        )
        if (
            pvc is None
            or (pvc.session_id, pvc.sandbox_id, pvc.uid)
            != (row.session_id, row.sandbox_id, row.pvc_uid)
            or str(pvc.pvc_id) != old["payload"]["pvc_id"]
            or pvc.uid != old["uid"]
            or pvc.state not in ("detached", "attaching")
            or (row.status == "stopped" and pvc.state != "detached")
            or (row.status == "creating" and pvc.state != "attaching")
            or row.status not in ("stopped", "creating")
            or row.golden_version != saved.journal["snapshot"]["golden_version"]
        ):
            raise PairClaimLost("retained workspace lifetime or claim changed")
        state = await db.get(
            EgressState,
            UUID(saved.journal["snapshot"]["egress_state_id"]),
            with_for_update=True,
            populate_existing=True,
        )
        if state is None or state_snapshot(state) != saved.journal["snapshot"]["egress_state"]:
            raise PairClaimLost("retained persistent state or wrapping identity changed")
        return saved, state, pvc

    async def inherit(
        self,
        db: AsyncSession,
        row: SandboxSession,
        pair: PairIntent,
        saved: PairRetirement,
        state: EgressState,
        pvc: SessionPVC,
    ) -> PairTransfer:
        """Same transaction as allocating the new generation under its claim.

        The inherited settled entries refer to original completed publications,
        not new create-capable invocations. The one-use receipt makes that
        provenance explicit; no publisher may redispatch them.
        """
        await PairIntentRepository()._owned(db, row, pair.claim_owner)
        if (
            pair.generation == saved.generation
            or pair.retired_at is not None
            or pair.creation_fenced
            or (pair.session_id, pair.sandbox_id, pair.project_id, pair.claim_changed)
            != (row.session_id, row.sandbox_id, row.project_id, row.status_changed_at)
            or pair.namespace != saved.journal["snapshot"]["namespace"]
            or pair.golden_version != saved.journal["snapshot"]["golden_version"]
            or pair.claim_changed <= saved.retired_at
            or pair.egress_state_id is not None
            or pair.retained_from is not None
            or pair.volume_resources["workspace"]["dispatch"] != "unissued"
            or pair.topics_dispatch != "unissued"
            or state_snapshot(state) != saved.journal["snapshot"]["egress_state"]
            or pvc.state != "attaching"
            or pvc.pvc_id != row.pvc_id
            or pvc.uid != row.pvc_uid
            or (saved.session_id, saved.sandbox_id, saved.project_id)
            != (pair.session_id, pair.sandbox_id, pair.project_id)
            or str(pvc.pvc_id)
            != saved.journal["snapshot"]["volume_resources"]["workspace"]["payload"]["pvc_id"]
            or pvc.uid != saved.journal["snapshot"]["volume_resources"]["workspace"]["uid"]
        ):
            raise PairClaimLost("new retained ownership scope changed")
        # The caller may not inject an available-looking receipt: validate it
        # again from the immutable original row while the locks remain held.
        original = await self.retirements.verify(db, saved.generation)
        if original.journal_sha256 != saved.journal_sha256 or original.kind != "idle":
            raise PairClaimLost("retained predecessor proof changed")
        workspace = deepcopy(saved.journal["snapshot"]["volume_resources"]["workspace"])
        workspace["payload"]["pvc_changed"] = pvc.last_state_change.isoformat()
        transfer = PairTransfer(
            generation=pair.generation,
            predecessor=saved.generation,
            session_id=pair.session_id,
            sandbox_id=pair.sandbox_id,
            project_id=pair.project_id,
            claim_owner=pair.claim_owner,
            claim_changed=pair.claim_changed,
            retirement_sha256=saved.journal_sha256,
            state=state_snapshot(state),
            workspace=workspace,
        )
        db.add(transfer)
        pair.retained_from = saved.generation
        pair.egress_state_id = state.state_id
        pair.volume_resources = {**pair.volume_resources, "workspace": workspace}
        pair.topics_dispatch = "settled"
        await db.flush()
        return transfer

    async def verify(self, db: AsyncSession, pair: PairIntent) -> PairTransfer | None:
        receipt = await db.get(
            PairTransfer, pair.generation, with_for_update=True, populate_existing=True
        )
        if receipt is None:
            if pair.retained_from is not None:
                raise PairClaimLost("retained generation transfer receipt missing")
            return None
        previous = await self.retirements.verify(db, receipt.predecessor)
        if (
            pair.retained_from != receipt.predecessor
            or previous.kind != "idle"
            or previous.journal_sha256 != receipt.retirement_sha256
            or previous.retired_at >= pair.claim_changed
            or (
                receipt.session_id,
                receipt.sandbox_id,
                receipt.project_id,
                receipt.claim_owner,
                receipt.claim_changed,
            )
            != (
                pair.session_id,
                pair.sandbox_id,
                pair.project_id,
                pair.claim_owner,
                pair.claim_changed,
            )
            or (previous.session_id, previous.sandbox_id, previous.project_id)
            != (pair.session_id, pair.sandbox_id, pair.project_id)
            or pair.egress_state_id is None
            or str(pair.egress_state_id) != receipt.state["state_id"]
            or receipt.state != previous.journal["snapshot"]["egress_state"]
            or pair.volume_resources["workspace"] != receipt.workspace
            or pair.topics_dispatch != "settled"
        ):
            raise PairClaimLost("retained ownership receipt changed")
        original = deepcopy(previous.journal["snapshot"]["volume_resources"]["workspace"])
        original["payload"]["pvc_changed"] = receipt.workspace["payload"]["pvc_changed"]
        if original != receipt.workspace:
            raise PairClaimLost("retained workspace provenance changed")
        state = await db.get(
            EgressState, pair.egress_state_id, with_for_update=True, populate_existing=True
        )
        if state is None or state_snapshot(state) != receipt.state:
            raise PairClaimLost("retained state provenance changed")
        return receipt
