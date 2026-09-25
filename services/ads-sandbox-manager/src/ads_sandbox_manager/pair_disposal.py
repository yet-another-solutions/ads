"""Exclusive expiry of positively retired retained storage, never a new runtime."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import msgspec
from sqlalchemy import DateTime, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_commons.sandbox.block_release import decode_block_release
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_resource_teardown import PairResourceTeardown
from ads_sandbox_manager.pair_retirement import PairRetirement, PairRetirementRepository
from ads_sandbox_manager.pair_store import PairClaimLost
from ads_sandbox_manager.store import Base, SandboxSession, SessionPVC, advance


def retained_targets(saved: PairRetirement) -> Object:
    journal = saved.journal
    targets = {}
    for role in ("workspace", "state"):
        original = (
            journal["storage_capture"].get(role)
            or journal["partial_storage"].get(role)
            or journal["unused_storage"].get(role, {}).get("capture", {}).get("target")
        )
        if original is None or not original["retain"]:
            raise PairClaimLost("retained lifetime has no original storage release")
        targets[role] = {**deepcopy(original), "retain": False}
    return targets


def original_block(saved: PairRetirement, role: str) -> Object | None:
    if saved.journal["block_disposition"].get(role) == "retained":
        return cast(Object | None, saved.journal["block_capture"])
    unused = saved.journal["unused_storage"].get(role)
    if unused and unused["capture"]["mode"] == "retired-inherited-csi":
        return cast(Object | None, unused["capture"]["previous"]["block_capture"])
    return None


def originally_never_mounted(saved: PairRetirement, role: str) -> bool:
    unused = saved.journal["unused_storage"].get(role)
    return bool(
        unused
        and unused["disposition"] == "retained"
        and (
            unused["capture"]["mode"] == "never-mounted-csi"
            or (
                unused["capture"]["mode"] == "retired-inherited-csi"
                and unused["capture"]["previous"]["never_mounted"]
            )
        )
    )


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
    retirement_sha256: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    targets: Mapped[Object] = mapped_column(JSONB)
    block_release: Mapped[Object | None] = mapped_column(JSONB)
    dispositions: Mapped[Object] = mapped_column(JSONB)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PairDisposalRepository:
    def __init__(self, lifecycle: LifecycleRepository) -> None:
        self.lifecycle = lifecycle
        self.retirements = PairRetirementRepository(lifecycle)

    async def orphan_scope(self, db: AsyncSession, saved: PairRetirement) -> None:
        owner = await db.scalar(
            select(SandboxSession.session_id)
            .where(
                or_(
                    SandboxSession.session_id == saved.session_id,
                    SandboxSession.sandbox_id == saved.sandbox_id,
                )
            )
            .with_for_update()
        )
        pvc = await db.scalar(
            select(SessionPVC.pvc_id).where(SessionPVC.session_id == saved.session_id).limit(1)
        )
        recovery = await db.scalar(
            select(CleanupWork.work_id)
            .where(
                CleanupWork.kind == "recovery",
                or_(
                    CleanupWork.session_id == saved.session_id,
                    CleanupWork.sandbox_id == saved.sandbox_id,
                ),
            )
            .limit(1)
        )
        if owner is not None or pvc is not None or recovery is not None:
            raise PairClaimLost("retained orphan has a live ownership claim")

    async def begin(
        self, db: AsyncSession, work: CleanupWork, saved: PairRetirement, now: datetime
    ) -> PairDisposal:
        from ads_sandbox_manager.pair_transfer import PairTransfer

        # Session and original generation locks serialize this with resume.
        original = await self.retirements.verify(db, saved.generation)
        if (
            work.kind not in ("reap", "orphan")
            or not await self.lifecycle.owns(db, work)
            or original.kind not in ("idle", "orphan-retained")
            or original.journal_sha256 != saved.journal_sha256
            or work.sandbox_id != saved.sandbox_id
            or await db.scalar(
                select(PairTransfer.generation).where(PairTransfer.predecessor == saved.generation)
            )
            is not None
        ):
            raise PairClaimLost("retained expiry claim changed")
        targets = retained_targets(original)
        pvc_id = UUID(
            saved.journal["snapshot"]["volume_resources"]["workspace"]["payload"]["pvc_id"]
        )
        if work.kind == "orphan":
            if work.session_id is not None or work.pvc_id is not None:
                raise PairClaimLost("retained orphan work has a session binding")
            await self.orphan_scope(db, saved)
        else:
            pvc = await db.get(SessionPVC, work.pvc_id, with_for_update=True)
            if (
                work.session_id != saved.session_id
                or pvc is None
                or pvc.pvc_id != pvc_id
                or pvc.uid != targets["workspace"]["uid"]
            ):
                raise PairClaimLost("retained expiry workspace changed")
        receipt = PairDisposal(
            generation=saved.generation,
            work_id=work.work_id,
            session_id=saved.session_id,
            sandbox_id=saved.sandbox_id,
            project_id=saved.project_id,
            pvc_id=pvc_id,
            pvc_uid=targets["workspace"]["uid"],
            retirement_sha256=saved.journal_sha256,
            created_at=now,
            targets=targets,
            dispositions={},
        )
        db.add(receipt)
        await db.flush()
        return receipt

    async def verify(self, db: AsyncSession, generation: UUID) -> PairDisposal:
        from ads_sandbox_manager.pair_transfer import PairTransfer

        saved = await self.retirements.verify(db, generation)
        receipt = await db.get(
            PairDisposal, generation, with_for_update=True, populate_existing=True
        )
        if (
            receipt is None
            or saved.kind not in ("idle", "orphan-retained")
            or (receipt.session_id, receipt.sandbox_id, receipt.project_id)
            != (saved.session_id, saved.sandbox_id, saved.project_id)
            or receipt.retirement_sha256 != saved.journal_sha256
            or receipt.targets != retained_targets(saved)
            or receipt.pvc_uid != receipt.targets["workspace"]["uid"]
            or str(receipt.pvc_id)
            != saved.journal["snapshot"]["volume_resources"]["workspace"]["payload"]["pvc_id"]
            or receipt.created_at < saved.retired_at
            or await db.scalar(
                select(PairTransfer.generation).where(PairTransfer.predecessor == generation)
            )
            is not None
            or not isinstance(receipt.dispositions, dict)
            or not set(receipt.dispositions) <= {"workspace", "state", "key", "topics"}
            or any(value != "deleted" for value in receipt.dispositions.values())
        ):
            raise PairClaimLost("retained disposal ownership or proof changed")
        if receipt.block_release is not None:
            if not isinstance(receipt.block_release, dict) or not set(receipt.block_release) <= {
                "workspace",
                "state",
            }:
                raise PairClaimLost("retained disposal has foreign Block roles")
            for role, raw in receipt.block_release.items():
                captured = original_block(saved, role)
                report = decode_block_release(msgspec.json.encode(raw))
                if (
                    captured is None
                    or not report.released
                    or role not in report.volumes
                    or any(
                        raw[key] != captured[key]
                        for key in captured
                        if key not in ("leftovers", "released")
                    )
                ):
                    raise PairClaimLost("retained disposal lost original Block identity")
        for role in ("workspace", "state"):
            if role in receipt.dispositions:
                if not (
                    receipt.targets[role]["delete_policy"]
                    and receipt.targets[role]["reclaim_guard"]
                    and (
                        (receipt.block_release is not None and role in receipt.block_release)
                        or originally_never_mounted(saved, role)
                    )
                ):
                    raise PairClaimLost("retained disposal lacks protected original release")
        if (
            "key" in receipt.dispositions
            and not {"workspace", "state"} <= receipt.dispositions.keys()
        ):
            raise PairClaimLost("custody disposed before retained storage")
        if "topics" in receipt.dispositions and "key" not in receipt.dispositions:
            raise PairClaimLost("topics disposed before retained custody")
        if receipt.completed_at is not None and (
            set(receipt.dispositions) != {"workspace", "state", "key", "topics"}
            or receipt.completed_at < receipt.created_at
        ):
            raise PairClaimLost("retained lifetime completion lacks dispositions")
        return receipt

    async def owned(self, db: AsyncSession, expected: CleanupWork) -> PairDisposal:
        if expected.session_id is None and expected.kind != "orphan":
            raise PairClaimLost("retained expiry requires a session claim")
        # Same order as admission: session/PVC before generation/receipt.
        if not await self.lifecycle.owns(db, expected):
            raise PairClaimLost("retained expiry claim lost")
        receipt = await db.scalar(
            select(PairDisposal).where(PairDisposal.work_id == expected.work_id)
        )
        if receipt is None:
            raise PairClaimLost("retained expiry receipt missing")
        receipt = await self.verify(db, receipt.generation)
        if expected.kind == "orphan":
            saved = await self.retirements.verify(db, receipt.generation)
            await self.orphan_scope(db, saved)
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
        if set(receipt.dispositions) != {"workspace", "state", "key", "topics"}:
            return False
        if work.kind != "orphan":
            row, pvc = await self.lifecycle.locked(db, receipt.session_id, receipt.sandbox_id)
            if row is None or pvc is None or pvc.uid != receipt.pvc_uid:
                raise PairClaimLost("retained expiry lifetime changed")
            row.pvc_id = row.pvc_uid = None
            # Destruction ends the stable identity. A later request starts a new sandbox.
            row.sandbox_id = uuid4()
            row.status_changed_at = advance(row.status_changed_at, now)
            await db.delete(pvc)
        receipt.completed_at = now
        stored = await db.get(CleanupWork, work.work_id)
        assert stored is not None
        await db.delete(stored)
        await db.flush()
        return True


class PairRetainedDisposal:
    def __init__(self, resources: PairResourceTeardown) -> None:
        self.resources = resources
        self.runtime = resources.runtime
        self.repository = PairDisposalRepository(self.runtime.repository)

    async def _checkpoint(self, work: CleanupWork) -> tuple[PairDisposal, PairRetirement]:
        async with self.runtime.sessions.begin() as db:
            receipt = await self.repository.owned(db, work)
            saved = await self.repository.retirements.verify(db, receipt.generation)
            return receipt, saved

    async def dispose(self, work: CleanupWork) -> bool:
        r = self.runtime
        async with asyncio.timeout(r.settings.cleanup_seconds):
            receipt, saved = await self._checkpoint(work)
            for role in ("workspace", "state"):
                receipt, saved = await self._checkpoint(work)
                if role in receipt.dispositions:
                    continue
                target = receipt.targets[role]
                if not (target["delete_policy"] and target["reclaim_guard"]):
                    return False
                captured = original_block(saved, role)
                if captured is not None:
                    if r.node_owner is None:
                        return False
                    raw = await r.node_owner.observe_block(
                        decode_block_release(msgspec.json.encode(captured))
                    )
                    report = decode_block_release(raw)
                    if not report.released:
                        return False
                    async with r.sessions.begin() as db:
                        current = await self.repository.owned(db, work)
                        current.block_release = {
                            **(current.block_release or {}),
                            role: msgspec.to_builtins(report),
                        }
                        await db.flush()
                        await self.repository.verify(db, current.generation)
                elif not originally_never_mounted(saved, role):
                    return False
                if not await r.storage.unreferenced(target):
                    return False
                obj = await r.storage.observe(target)
                if obj is not None:
                    current_target = await r.storage.capture(
                        {key: target[key] for key in ("kind", "name", "uid", "retain")}
                    )
                    if any(
                        current_target.get(key) != target[key]
                        for key in (
                            "uid",
                            "pv_uid",
                            "pv_name",
                            "volume_key",
                            "delete_policy",
                            "reclaim_guard",
                        )
                    ):
                        raise PairClaimLost("retained original backing changed")
                await self._checkpoint(work)
                await r.storage.delete(target)
                # Started storage uses the original nodes. Never-mounted storage
                # has separate positive history; API absence is only the final
                # CSI Delete+finalizer contract, never its runtime release proof.
                if target["nodes"]:
                    done = await r.storage.reclaimed(target)
                else:
                    done = await r.storage.dispose_unused(
                        {**saved.journal["unused_storage"][role]["capture"], "target": target}
                    )
                if not done:
                    return False
                async with r.sessions.begin() as db:
                    current = await self.repository.owned(db, work)
                    current.dispositions = {**current.dispositions, role: "deleted"}
            receipt, saved = await self._checkpoint(work)
            pair = r.repository.cleanup_pair(
                CleanupWork(
                    sandbox_id=saved.sandbox_id,
                    session_id=saved.session_id,
                    pair_snapshot=saved.journal["snapshot"],
                )
            )
            if "key" not in receipt.dispositions:
                state = saved.journal["snapshot"]["egress_state"]
                if not await self.resources.kube.dispose_secret(
                    pair, "state-key", state["key_uid"], persistent=state
                ):
                    return False
                async with r.sessions.begin() as db:
                    current = await self.repository.owned(db, work)
                    current.dispositions = {**current.dispositions, "key": "deleted"}
            receipt, _ = await self._checkpoint(work)
            if "topics" not in receipt.dispositions:
                if not await self.resources.topics.remove(receipt.sandbox_id):
                    return False
                async with r.sessions.begin() as db:
                    current = await self.repository.owned(db, work)
                    current.dispositions = {**current.dispositions, "topics": "deleted"}
            async with r.sessions.begin() as db:
                return await self.repository.finish(db, work, datetime.now(UTC))
