from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, delete, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_sandbox_manager.pair_compute_inputs import validate_compute_payloads
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.pair_store import (
    CONTROL_RESOURCES,
    PairClaimLost,
    PairIntent,
    compute_key,
    new_compute_uids,
    resource_key,
    validate_compute_evidence,
    validate_control_dispatch,
    validate_relay_custody,
)
from ads_sandbox_manager.relay_inputs import input_role, validate_relay_inputs
from ads_sandbox_manager.session_objects import (
    CA_CONSUMERS,
    ca_consumer_name,
    ipc_name,
    session_name,
)
from ads_sandbox_manager.store import Base, PingProbe, SandboxSession, SessionPVC, advance


class CleanupWork(Base):
    """Restart-safe intent and captured targets. Never contains JWTs or execution data."""

    __tablename__ = "cleanup_work"

    work_id: Mapped[UUID] = mapped_column(primary_key=True)
    session_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sandbox_session.session_id", ondelete="CASCADE"), index=True
    )
    sandbox_id: Mapped[UUID]
    pvc_id: Mapped[UUID | None]
    kind: Mapped[str]
    state_changed: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    pvc_changed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    acknowledged: Mapped[bool] = mapped_column(default=False)
    targets: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    pair_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


def target(kind: str, name: str, uid: str | None, *, retain: bool = False) -> dict[str, Any]:
    return {"kind": kind, "name": name, "uid": uid, "retain": retain}


def sandbox_targets(row: SandboxSession, *, retain: bool) -> list[dict[str, Any]]:
    objects = [
        target("Deployment", ipc_name(row.sandbox_id), row.ipc_deployment_uid),
        target("Deployment", session_name(row.sandbox_id), row.guest_deployment_uid),
        target("PersistentVolumeClaim", ipc_name(row.sandbox_id), row.ipc_pvc_uid),
    ]
    if row.ca_attempt is not None:
        objects.extend(
            target(
                "PersistentVolumeClaim",
                ca_consumer_name(row.sandbox_id, role),
                (row.ca_clones or {}).get(role),
            )
            for role in CA_CONSUMERS
        )
    if row.pvc_id:
        objects.append(
            target("PersistentVolumeClaim", session_name(row.pvc_id), row.pvc_uid, retain=retain)
        )
    return objects


class LifecycleRepository:
    """All joint mutations lock sandbox then its PVC. External work follows commit."""

    async def locked(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
    ) -> tuple[SandboxSession | None, SessionPVC | None]:
        row = await db.get(SandboxSession, session_id, with_for_update=True)
        if row is None or row.sandbox_id != sandbox_id:
            return None, None
        pvc = await db.get(SessionPVC, row.pvc_id, with_for_update=True) if row.pvc_id else None
        return row, pvc

    async def pair_snapshot(
        self, db: AsyncSession, session_id: UUID, sandbox_id: UUID
    ) -> dict[str, Any] | None:
        """Capture the original pair, never follow a replacement session mapping."""
        intent = await db.scalar(
            select(PairIntent)
            .where(PairIntent.sandbox_id == sandbox_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if intent is None:
            return None
        if intent.session_id != session_id:
            raise RuntimeError("pair cleanup session identity mismatch")
        validate_relay_custody(intent.relay_custody)
        validate_compute_payloads(intent.compute_payloads)
        validate_relay_inputs(intent.binding(), intent.relay_inputs)
        return {
            "generation": str(intent.generation),
            "session_id": str(intent.session_id),
            "sandbox_id": str(intent.sandbox_id),
            "project_id": str(intent.project_id),
            "namespace": intent.namespace,
            "golden_version": intent.golden_version,
            "control_uids": dict(intent.control_uids),
            "compute_uids": dict(intent.compute_uids),
            "compute_payloads": dict(intent.compute_payloads),
            "relay_custody": dict(intent.relay_custody),
            "relay_inputs": dict(intent.relay_inputs),
            "egress_state_id": str(intent.egress_state_id) if intent.egress_state_id else None,
        }

    async def work(
        self,
        db: AsyncSession,
        row: SandboxSession,
        pvc: SessionPVC | None,
        kind: str,
        now: datetime,
        timeout: float,
        targets: list[dict[str, Any]],
    ) -> CleanupWork:
        work = CleanupWork(
            work_id=uuid4(),
            session_id=row.session_id,
            sandbox_id=row.sandbox_id,
            pvc_id=pvc.pvc_id if pvc else None,
            kind=kind,
            state_changed=row.status_changed_at,
            pvc_changed=pvc.last_state_change if pvc else None,
            deadline=now + timedelta(seconds=timeout),
            targets=targets,
            acknowledged=False,
            pair_snapshot=await self.pair_snapshot(db, row.session_id, row.sandbox_id),
        )
        db.add(work)
        return work

    async def idle(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
        now: datetime,
        inactivity: float,
        timeout: float,
    ) -> CleanupWork | None:
        row, pvc = await self.locked(db, session_id, sandbox_id)
        cutoff = now - timedelta(seconds=inactivity)
        if (
            row is None
            or row.status != "ready"
            or row.last_execution_at > cutoff
            or pvc is None
            or pvc.state != "attached"
            or pvc.last_execution > cutoff
        ):
            return None
        row.status = "shutting_down"
        row.status_changed_at = advance(row.status_changed_at, now)
        pvc.state = "detaching"
        pvc.last_state_change = advance(pvc.last_state_change, now)
        return await self.work(
            db, row, pvc, "idle", now, timeout, sandbox_targets(row, retain=True)
        )

    async def reap(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
        pvc_id: UUID,
        now: datetime,
        inactivity: float,
        detached: float,
        timeout: float,
    ) -> CleanupWork | None:
        row, pvc = await self.locked(db, session_id, sandbox_id)
        if (
            row is None
            or row.status != "stopped"
            or pvc is None
            or pvc.pvc_id != pvc_id
            or pvc.state != "detached"
            or pvc.last_execution > now - timedelta(seconds=inactivity)
            or row.last_execution_at > now - timedelta(seconds=inactivity)
            or pvc.last_state_change > now - timedelta(seconds=detached)
        ):
            return None
        pvc.state = "destroying"
        pvc.last_state_change = advance(pvc.last_state_change, now)
        return await self.work(
            db,
            row,
            pvc,
            "reap",
            now,
            timeout,
            [
                {
                    **(pvc.release_evidence or {}),
                    **target("PersistentVolumeClaim", session_name(pvc_id), pvc.uid),
                }
            ],
        )

    async def service(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
        now: datetime,
        timeout: float,
        targets: list[dict[str, Any]],
    ) -> CleanupWork | None:
        row, pvc = await self.locked(db, session_id, sandbox_id)
        if row is None or row.status != "stopped" or (pvc is not None and pvc.state != "detached"):
            return None
        row.status = "service"
        row.status_changed_at = advance(row.status_changed_at, now)
        row.service_deadline = now + timedelta(seconds=timeout)
        return await self.work(db, row, pvc, "service", now, timeout, targets)

    async def owns(self, db: AsyncSession, work: CleanupWork) -> bool:
        if work.kind == "orphan":
            return True  # Each exact object is independently revalidated before deletion.
        if work.session_id is None:
            return False
        row, pvc = await self.locked(db, work.session_id, work.sandbox_id)
        state = {"idle": "shutting_down", "reap": "stopped", "service": "service"}.get(work.kind)
        return (
            row is not None
            and row.status == state
            and row.status_changed_at == work.state_changed
            and row.pvc_id == work.pvc_id
            and (
                (pvc is None and work.pvc_id is None)
                or (
                    pvc is not None
                    and pvc.last_state_change == work.pvc_changed
                    and pvc.state
                    == {"idle": "detaching", "reap": "destroying", "service": "detached"}[work.kind]
                )
            )
        )

    @staticmethod
    def cleanup_pair(work: CleanupWork) -> PairBinding:
        snapshot = work.pair_snapshot
        fields = {
            "generation",
            "session_id",
            "sandbox_id",
            "project_id",
            "namespace",
            "golden_version",
            "control_uids",
            "compute_uids",
            "relay_custody",
            "relay_inputs",
            "compute_payloads",
            "egress_state_id",
        }
        if not isinstance(snapshot, dict) or set(snapshot) != fields:
            raise RuntimeError("incomplete pair cleanup snapshot")
        validate_relay_custody(snapshot["relay_custody"])
        state_id = snapshot["egress_state_id"]
        if state_id is not None and (
            not isinstance(state_id, str) or str(UUID(state_id)) != state_id
        ):
            raise RuntimeError("invalid persistent egress cleanup anchor")
        identities = {}
        for field in ("session_id", "sandbox_id", "project_id", "generation"):
            value = snapshot[field]
            if not isinstance(value, str) or str(UUID(value)) != value:
                raise RuntimeError("invalid pair cleanup identity")
            identities[field] = UUID(value)
        pair = PairBinding(**identities)
        validate_relay_inputs(pair, snapshot["relay_inputs"])
        validate_compute_payloads(snapshot["compute_payloads"])
        controls = snapshot["control_uids"]
        compute = snapshot["compute_uids"]
        if (
            pair.sandbox_id != work.sandbox_id
            or (work.kind != "orphan" and pair.session_id != work.session_id)
            or (work.kind == "orphan" and work.session_id is not None)
            or any(
                not isinstance(snapshot[k], str) or not snapshot[k].strip()
                for k in ("namespace", "golden_version")
            )
            or not isinstance(controls, dict)
            or set(controls) != {resource_key(*item) for item in CONTROL_RESOURCES}
            or any(
                uid is not None and (not isinstance(uid, str) or not uid.strip())
                for uid in controls.values()
            )
            or not isinstance(compute, dict)
            or set(compute) != set(new_compute_uids())
            or any(
                uid is not None and (not isinstance(uid, str) or not uid.strip())
                for uid in compute.values()
            )
        ):
            raise RuntimeError("pair cleanup scope or controls changed")
        return pair

    async def owned_pair_cleanup(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> CleanupWork:
        """Read-only capture authority; never authorizes deletion or retirement."""
        fields = (
            "work_id",
            "session_id",
            "sandbox_id",
            "pvc_id",
            "kind",
            "state_changed",
            "pvc_changed",
        )
        identity = tuple(getattr(expected, key) for key in fields)
        snapshot = expected.pair_snapshot
        targets = expected.targets
        if expected.kind == "orphan" and expected.session_id is not None:
            raise PairClaimLost("invalid pair orphan claim")
        if expected.kind == "recovery" and recovery is None:
            raise PairClaimLost("pair recovery claim required")
        pair = self.cleanup_pair(expected)
        assert snapshot is not None
        if expected.kind == "recovery":
            if recovery is None or recovery.session_id != pair.session_id:
                raise PairClaimLost("pair recovery claim required")
            row = await db.get(SandboxSession, recovery.session_id, with_for_update=True)
            if (
                row is None
                or (row.sandbox_id, row.project_id, row.status_changed_at)
                != (recovery.sandbox_id, recovery.project_id, recovery.status_changed_at)
                or row.status != "recovering"
                or row.project_id != pair.project_id
                or row.pvc_id is not None
                or row.claimed_by is not None
                or row.status_changed_at + timedelta(seconds=recovery_seconds) <= now
                or any(obj.get("retain") for obj in targets)
            ):
                raise PairClaimLost("pair recovery claim changed")
            if expected.pvc_id is not None:
                pvc = await db.get(SessionPVC, expected.pvc_id, with_for_update=True)
                if pvc is None or pvc.session_id != pair.session_id or pvc.state != "failed":
                    raise PairClaimLost("pair recovery PVC ownership changed")
        elif expected.kind == "orphan":
            if recovery is not None or expected.pvc_id is not None:
                raise PairClaimLost("invalid pair orphan claim")
            # Deliberately conservative: a replacement session or retained PVC
            # blocks this read-only path too. Absent-row checks are not a fence
            # against future insertion and must never become delete authority.
            owner = await db.scalar(
                select(SandboxSession.session_id)
                .where(
                    or_(
                        SandboxSession.session_id == pair.session_id,
                        SandboxSession.sandbox_id == pair.sandbox_id,
                    )
                )
                .with_for_update()
            )
            pvc_owner = await db.scalar(
                select(SessionPVC.pvc_id).where(SessionPVC.session_id == pair.session_id)
            )
            recovery_owner = await db.scalar(
                select(CleanupWork.work_id).where(
                    CleanupWork.kind == "recovery",
                    or_(
                        CleanupWork.session_id == pair.session_id,
                        CleanupWork.sandbox_id == pair.sandbox_id,
                    ),
                )
            )
            if owner is not None or pvc_owner is not None or recovery_owner is not None:
                raise PairClaimLost("pair orphan acquired an owner")
            intent = await db.get(PairIntent, pair.generation, with_for_update=True)
            if (
                intent is None
                or intent.binding() != pair
                or intent.namespace != snapshot["namespace"]
                or intent.golden_version != snapshot["golden_version"]
            ):
                raise PairClaimLost("pair orphan durable identity changed")
        elif (
            recovery is not None
            or expected.kind not in ("idle", "service", "reap")
            or not await self.owns(db, expected)
        ):
            raise PairClaimLost("pair cleanup claim changed")
        # Preserve session/PVC -> work lock order; no external call in this transaction.
        stored = await db.get(
            CleanupWork, expected.work_id, with_for_update=True, populate_existing=True
        )
        if (
            stored is None
            or tuple(getattr(stored, key) for key in fields) != identity
            or stored.pair_snapshot != snapshot
            or stored.targets != targets
            or (stored.kind in ("idle", "service", "reap") and stored.deadline <= now)
            or (stored.kind == "idle" and not stored.acknowledged)
        ):
            raise PairClaimLost("pair cleanup work changed or not drained")
        pair = self.cleanup_pair(stored)
        if stored.kind != "orphan":
            row = await db.get(SandboxSession, pair.session_id)
            if row is None or row.project_id != pair.project_id:
                raise PairClaimLost("pair cleanup project identity changed")
        return stored

    async def record_pair_control(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        kind: str,
        role: str,
        uid: str | None,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> CleanupWork:
        """Capture an observed UID, never turn one absent read into retirement."""
        key = resource_key(kind, role)
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid observed pair control UID")
        work = await self.owned_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        )
        assert work.pair_snapshot is not None
        controls = work.pair_snapshot["control_uids"]
        previous = controls[key]
        if uid is not None:
            if previous is not None and previous != uid:
                raise RuntimeError("pair cleanup UID replacement refused")
            work.pair_snapshot = {
                **work.pair_snapshot,
                "control_uids": {**controls, key: uid},
            }
            await db.flush()
        return work

    async def record_pair_compute(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        role: str,
        uid: str | None,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> CleanupWork:
        """Capture observed compute ownership, never settlement or absence."""
        key = compute_key(role)
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid observed pair compute UID")
        work = await self.owned_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        )
        assert work.pair_snapshot is not None
        compute = work.pair_snapshot["compute_uids"]
        if uid is not None:
            previous = compute[key]
            if previous is not None and previous != uid:
                raise RuntimeError("pair cleanup compute UID replacement refused")
            work.pair_snapshot = {
                **work.pair_snapshot,
                "compute_uids": {**compute, key: uid},
            }
            await db.flush()
        return work

    async def fence_pair_creators(self, db: AsyncSession, work: CleanupWork) -> PairIntent:
        """Caller must own this cleanup claim in the same short transaction.

        Fence future dispatch, not already reserved work. Inflight markers
        survive capture/absence and are not runtime-release evidence.
        """
        pair = self.cleanup_pair(work)
        assert work.pair_snapshot is not None
        intent = await db.get(
            PairIntent, pair.generation, with_for_update=True, populate_existing=True
        )
        if (
            intent is None
            or intent.binding() != pair
            or intent.namespace != work.pair_snapshot["namespace"]
            or intent.golden_version != work.pair_snapshot["golden_version"]
        ):
            raise PairClaimLost("pair creator fence identity changed")
        validate_control_dispatch(intent)
        validate_compute_evidence(intent)
        validate_relay_custody(intent.relay_custody)
        validate_relay_inputs(intent.binding(), intent.relay_inputs)
        validate_compute_payloads(intent.compute_payloads)
        state_id = str(intent.egress_state_id) if intent.egress_state_id else None
        if state_id != work.pair_snapshot["egress_state_id"]:
            raise PairClaimLost("persistent egress cleanup anchor changed")
        if intent.compute_payloads != work.pair_snapshot["compute_payloads"]:
            raise PairClaimLost("pair compute cleanup payload changed")
        if any(
            intent.relay_inputs[role]["payload"] != entry["payload"]
            for role, entry in work.pair_snapshot["relay_inputs"].items()
        ):
            raise PairClaimLost("relay input cleanup payload changed")
        if (
            intent.relay_custody["public_keys"]
            != work.pair_snapshot["relay_custody"]["public_keys"]
        ):
            raise PairClaimLost("relay custody cleanup identity changed")
        intent.creation_fenced = True
        await db.flush()
        return intent

    async def record_relay_custody(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        uid: str | None,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> CleanupWork:
        """Capture only a UID; never copy key material or settle a dispatch."""
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid relay custody UID")
        work = await self.owned_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        )
        assert work.pair_snapshot is not None
        custody = work.pair_snapshot["relay_custody"]
        if custody["public_keys"] is None:
            raise RuntimeError("relay custody was never dispatched")
        if uid is not None:
            if custody["uid"] is not None and custody["uid"] != uid:
                raise RuntimeError("relay custody cleanup UID replacement refused")
            work.pair_snapshot = {
                **work.pair_snapshot,
                "relay_custody": {**custody, "uid": uid},
            }
            await db.flush()
        return work

    async def record_relay_input(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        role: str,
        uid: str | None,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> CleanupWork:
        input_role(role)
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid relay input UID")
        work = await self.owned_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        )
        assert work.pair_snapshot is not None
        inputs = work.pair_snapshot["relay_inputs"]
        entry = inputs[role]
        if entry["payload"] is None:
            raise RuntimeError("relay input was never dispatched")
        if uid is not None:
            if entry["uid"] is not None and entry["uid"] != uid:
                raise RuntimeError("relay input cleanup UID replacement refused")
            work.pair_snapshot = {
                **work.pair_snapshot,
                "relay_inputs": {**inputs, role: {**entry, "uid": uid}},
            }
            await db.flush()
        return work

    async def complete(self, db: AsyncSession, work: CleanupWork, now: datetime) -> bool:
        if not await self.owns(db, work):
            return False
        stored = await db.get(CleanupWork, work.work_id, populate_existing=True)
        if stored is None or stored.pair_snapshot is not None:
            # Guest/IPC deletion alone cannot retire paired runtime ownership.
            # Preserve even malformed/empty snapshots rather than erase evidence.
            return False
        if work.session_id is not None:
            row, pvc = await self.locked(db, work.session_id, work.sandbox_id)
            assert row is not None
            if work.kind == "reap":
                assert pvc is not None
                row.pvc_id = None
                row.pvc_uid = None
                await db.delete(pvc)
            else:
                row.status = "stopped"
                row.status_changed_at = advance(row.status_changed_at, now)
                row.service_deadline = None
                row.guest_deployment_uid = row.ipc_deployment_uid = row.ipc_pvc_uid = None
                row.ca_attempt = row.ca_sources = row.ca_clones = None
                if work.kind == "idle":
                    assert pvc is not None
                    pvc.state = "detached"
                    pvc.last_state_change = advance(pvc.last_state_change, now)
                    pvc.release_evidence = next(t for t in work.targets if t.get("retain"))
        await db.delete(stored)
        return True

    async def recover(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
        now: datetime,
        timeout: float,
    ) -> bool:
        """Fence recovery from idle retention, including delayed published verdicts."""
        row, pvc = await self.locked(db, session_id, sandbox_id)
        if row is None:
            return False
        if row.status == "shutting_down" or (
            row.status == "stopped" and (pvc is None or pvc.state != "destroying")
        ):
            return False
        previous = list(
            await db.scalars(select(CleanupWork).where(CleanupWork.session_id == session_id))
        )
        # A legacy timeout may already have reclassified an idle intent as recovery.
        # Retention is not deletion authority, even after a restart or ID rotation.
        if any(obj.get("retain") for work in previous for obj in work.targets):
            return False
        if row.status == "recovering":
            if row.status_changed_at > now - timedelta(seconds=timeout):
                return False
            row.status = "failed"
        old = await self.work(
            db, row, pvc, "recovery", now, timeout, sandbox_targets(row, retain=False)
        )
        if pvc and pvc.release_evidence:
            old.targets = [
                {**pvc.release_evidence, **obj} if obj["name"] == session_name(pvc.pvc_id) else obj
                for obj in old.targets
            ]
        # Preserve prior evidence and every unfinished generation, rather than replace it.
        for work in previous:
            work.kind = "recovery"
            if work.pair_snapshot is None:
                work.pair_snapshot = await self.pair_snapshot(db, session_id, work.sandbox_id)
        old.kind = "recovery"
        row.sandbox_id = uuid4()
        row.status = "recovering"
        row.status_changed_at = advance(row.status_changed_at, now)
        row.service_deadline = None
        row.claimed_by = None
        row.pvc_id = row.pvc_uid = None
        row.guest_deployment_uid = row.ipc_deployment_uid = row.ipc_pvc_uid = None
        row.ca_attempt = row.ca_sources = row.ca_clones = None
        row.last_ping_at = row.last_ping_sent_at = None
        await db.execute(delete(PingProbe).where(PingProbe.sandbox_id == sandbox_id))
        if pvc:
            pvc.state = "failed"
            pvc.last_state_change = advance(pvc.last_state_change, now)
        return True
