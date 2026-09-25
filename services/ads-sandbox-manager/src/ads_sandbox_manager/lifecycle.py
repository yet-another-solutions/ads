from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Literal
from uuid import UUID, uuid4

import msgspec
from sqlalchemy import delete, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_commons.sandbox import SandboxPing, SandboxShutdown, encode_ping, encode_ready
from ads_sandbox_manager.auth import IPC, ClientCredentials, TokenMinter
from ads_sandbox_manager.cleanup import CleanupKubernetes
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository, target
from ads_sandbox_manager.objects import COMPONENT, Object
from ads_sandbox_manager.pair_block_storage import PairBlockStorageTeardown
from ads_sandbox_manager.pair_cleanup import PairCleanupCapture
from ads_sandbox_manager.pair_disposal import PairDisposal, PairRetainedDisposal
from ads_sandbox_manager.pair_ipc_storage import PairIpcStorageTeardown
from ads_sandbox_manager.pair_objects import GENERATION, PROJECT
from ads_sandbox_manager.pair_registry import PairRegistry
from ads_sandbox_manager.pair_resource_teardown import PairResourceTeardown
from ads_sandbox_manager.pair_retirement import PairRetirementRepository
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.pair_unused_storage import PairUnusedStorageTeardown
from ads_sandbox_manager.service import READY_TOPIC, Publisher
from ads_sandbox_manager.session_objects import (
    CA_CONSUMER,
    CA_CONSUMER_ROLE,
    SANDBOX,
    SESSION,
    ca_consumer_name,
    ipc_name,
    session_name,
)
from ads_sandbox_manager.store import PingProbe, SandboxSession, SessionPVC

log = logging.getLogger(__name__)
IDLE = "ads.sandbox.idle"
REAP = "ads.sandbox.pvc.reap"
ORPHAN = "ads.sandbox.orphan"
RECOVER = "ads.sandbox.recover"
TOPICS = (IDLE, REAP, ORPHAN, RECOVER)
PING_REQUEST = "ads.sandbox.ping.req"
PING_REPLY = "ads.sandbox.ping.res"


class Signal(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    session_id: UUID
    sandbox_id: UUID
    pvc_id: UUID | None = None
    kind: Literal["Deployment", "PersistentVolumeClaim"] | None = None
    name: str | None = None
    uid: str | None = None


class LifecycleService:
    """Authenticated signal admission, cluster scans, and restart-safe cleanup workers.

    DB transactions are short. Advisory session locks serialize scans/individual work
    across replicas without holding a SQL transaction over Kubernetes or Kafka I/O.
    """

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: LifecycleRepository,
        kube: CleanupKubernetes,
        publisher: Publisher,
        credentials: ClientCredentials,
        tokens: TokenMinter,
        pair_capture: PairCleanupCapture,
        pair_runtime: PairRuntimeTeardown | None = None,
        pair_resources: PairResourceTeardown | None = None,
    ) -> None:
        self.settings, self.sessions, self.repository = settings, sessions, repository
        self.kube, self.publisher, self.credentials, self.tokens = (
            kube,
            publisher,
            credentials,
            tokens,
        )
        self._task: asyncio.Task[None] | None = None
        self.pair_capture = pair_capture
        self.pair_runtime = pair_runtime
        self.pair_resources = pair_resources
        self._ping_task: asyncio.Task[None] | None = None
        self._pair_scan_after: UUID | None = None

    async def emit(self, topic: str, message: Signal) -> None:
        async with asyncio.timeout(self.settings.control_seconds):
            token = await asyncio.to_thread(self.credentials.mint)
            await self.publisher.send(
                topic, message.session_id, msgspec.json.encode(message), token
            )

    async def admit(self, topic: str, message: Signal) -> None:
        now, s = datetime.now(UTC), self.settings
        # Observe outside the DB transaction, then revalidate lifecycle ownership under lock.
        observed = await self.kube.inventory() if topic == ORPHAN else []
        async with asyncio.timeout(s.control_seconds), self.sessions.begin() as db:
            r = self.repository
            if topic == IDLE:
                await r.idle(
                    db,
                    message.session_id,
                    message.sandbox_id,
                    now,
                    s.idle_seconds,
                    s.cleanup_seconds,
                )
            elif topic == REAP and message.pvc_id:
                await r.reap(
                    db,
                    message.session_id,
                    message.sandbox_id,
                    message.pvc_id,
                    now,
                    s.idle_seconds,
                    s.detached_seconds,
                    s.cleanup_seconds,
                )
            elif topic == RECOVER:
                await r.recover(db, message.session_id, message.sandbox_id, now, s.recovery_seconds)
            elif topic == ORPHAN:
                await self._orphan(db, message, now, observed)

    async def shutdown_ack(self, sandbox_id: UUID, transition: datetime | None) -> None:
        if transition is None:
            return
        async with self.sessions.begin() as db:
            works = list(
                await db.scalars(
                    select(CleanupWork).where(
                        CleanupWork.sandbox_id == sandbox_id,
                        CleanupWork.kind == "idle",
                        CleanupWork.state_changed == transition,
                    )
                )
            )
            for work in works:
                if await self.repository.owns(db, work):
                    work.acknowledged = True

    async def ping_reply(self, message: SandboxPing) -> None:
        now = datetime.now(UTC)
        async with self.sessions.begin() as db:
            row = await db.scalar(
                select(SandboxSession)
                .where(SandboxSession.sandbox_id == message.sandbox_id)
                .with_for_update()
            )
            if row is None or row.status != "ready":
                return
            probe = await db.get(PingProbe, message.ping_id, with_for_update=True)
            if probe is None or probe.sandbox_id != row.sandbox_id:
                return
            if probe.sent_at < now - timedelta(seconds=self.settings.ping_timeout_seconds):
                return  # Keep confirmed timeout evidence until the scanner decides.
            row.last_ping_at = max(row.last_ping_at or now, now)
            await db.delete(probe)  # Duplicate replies cannot refresh liveness.

    async def ping_scan(self) -> None:
        now, s = datetime.now(UTC), self.settings
        async with self.sessions.begin() as db:
            await db.execute(
                delete(PingProbe).where(
                    PingProbe.sent_at < now - timedelta(seconds=s.ping_timeout_seconds),
                    or_(
                        PingProbe.published_at.is_(None),
                        ~select(SandboxSession.session_id)
                        .where(
                            SandboxSession.sandbox_id == PingProbe.sandbox_id,
                            SandboxSession.status == "ready",
                            or_(
                                SandboxSession.last_ping_at.is_(None),
                                SandboxSession.last_ping_at < PingProbe.published_at,
                            ),
                        )
                        .exists(),
                    ),
                )
            )
            rows = list(
                await db.scalars(
                    select(SandboxSession)
                    .where(
                        SandboxSession.status == "ready",
                        or_(
                            SandboxSession.last_ping_sent_at.is_(None),
                            SandboxSession.last_ping_sent_at
                            <= now - timedelta(seconds=s.ping_interval_seconds),
                        ),
                    )
                    .order_by(SandboxSession.last_ping_sent_at.asc().nullsfirst())
                    .limit(s.lifecycle_batch)
                )
            )
        for observed in rows:
            # Claim correlation before publication, outside any network-spanning transaction.
            async with self.sessions.begin() as db:
                row = await db.get(SandboxSession, observed.session_id, with_for_update=True)
                if row is None or row.sandbox_id != observed.sandbox_id or row.status != "ready":
                    continue
                timed_out = await db.scalar(
                    select(PingProbe.ping_id)
                    .where(
                        PingProbe.sandbox_id == row.sandbox_id,
                        PingProbe.published_at <= now - timedelta(seconds=s.ping_timeout_seconds),
                        PingProbe.published_at > (row.last_ping_at or row.status_changed_at),
                    )
                    .limit(1)
                )
                row.last_ping_sent_at = now
                message = SandboxPing(uuid4(), row.sandbox_id)
                if not timed_out:
                    db.add(
                        PingProbe(ping_id=message.ping_id, sandbox_id=row.sandbox_id, sent_at=now)
                    )
            if timed_out:
                await self.emit(RECOVER, Signal(observed.session_id, observed.sandbox_id))
            else:
                try:
                    async with asyncio.timeout(s.control_seconds):
                        subject = await asyncio.to_thread(self.credentials.mint)
                        context = await asyncio.to_thread(self.tokens.mint, IPC, subject)
                        if not context.access_token:
                            raise RuntimeError("ping STE returned no token")
                        await self.publisher.send(
                            PING_REQUEST,
                            message.sandbox_id,
                            encode_ping(message),
                            context.access_token,
                        )
                    async with self.sessions.begin() as db:
                        # A reply may already have consumed the correlation. A crash
                        # before this commit leaves an unconfirmed probe, never a
                        # death verdict. A later scan will send a fresh probe.
                        probe = await db.get(PingProbe, message.ping_id, with_for_update=True)
                        if probe is not None:
                            probe.published_at = datetime.now(UTC)
                except BaseException:
                    async with self.sessions.begin() as db:
                        await db.execute(
                            delete(PingProbe).where(PingProbe.ping_id == message.ping_id)
                        )
                    raise

    async def service_expired(self, row: SandboxSession) -> None:
        if row.service_deadline is not None and datetime.now(UTC) >= row.service_deadline:
            await self.emit(RECOVER, Signal(row.session_id, row.sandbox_id))

    async def _ownership(self, db: AsyncSession, message: Signal) -> str:
        if (
            await db.scalar(
                select(PairIntent.generation)
                .where(PairIntent.sandbox_id == message.sandbox_id)
                .limit(1)
            )
            is not None
        ):
            # The durable paired registry exclusively owns paired inventory.
            # Never reinterpret its state PVC or a lost session as legacy debris.
            return "owned"
        row = await db.get(SandboxSession, message.session_id, with_for_update=True)
        recovery = await db.scalars(
            select(CleanupWork).where(
                CleanupWork.session_id == message.session_id, CleanupWork.kind == "recovery"
            )
        )
        if any(
            obj["kind"] == message.kind
            and obj["name"] == message.name
            and obj["uid"] in (None, message.uid)
            and not obj.get("cleaned")
            for work in recovery
            for obj in work.targets
        ):
            return "owned"  # Recovery alone owns its persisted cleanup evidence.
        if message.kind == "PersistentVolumeClaim" and message.name:
            # Valid retained/attaching volumes are owned even before UID is recorded.
            pvcs = await db.scalars(
                select(SessionPVC).where(SessionPVC.session_id == message.session_id)
            )
            if any(session_name(p.pvc_id) == message.name for p in pvcs):
                return "owned"
        if row is not None and row.sandbox_id == message.sandbox_id:
            return "stopped" if row.status == "stopped" else "owned"
        return "orphan"

    async def _orphan(
        self,
        db: AsyncSession,
        message: Signal,
        now: datetime,
        observed: list[Object],
    ) -> None:
        if not message.kind or not message.name or not message.uid:
            return
        generation = await db.scalar(
            select(PairIntent.generation)
            .where(
                PairIntent.session_id == message.session_id,
                PairIntent.sandbox_id == message.sandbox_id,
            )
            .order_by(PairIntent.claim_changed.desc())
            .limit(1)
        )
        if generation is not None:
            # The suggestion only wakes the same exact ledger reconciliation
            # used by the periodic scan; its names/labels confer no authority.
            await PairRegistry(self.repository).reconcile(
                db, generation, now, self.settings.cleanup_seconds
            )
            return
        ownership = await self._ownership(db, message)
        objects = []
        for obj in observed:
            candidate = self.object_signal(obj)
            if candidate is None or (candidate.session_id, candidate.sandbox_id) != (
                message.session_id,
                message.sandbox_id,
            ):
                continue
            if await self._ownership(db, candidate) != ownership or ownership == "owned":
                continue
            assert candidate.name is not None
            objects.append(
                {
                    **target(obj["kind"], candidate.name, candidate.uid),
                    "session_id": str(message.session_id),
                    "sandbox_id": str(message.sandbox_id),
                }
            )
        if not any(
            o["uid"] == message.uid and o["name"] == message.name and o["kind"] == message.kind
            for o in objects
        ):
            return  # Stale/forged suggestion is never authority to delete arbitrary objects.
        objects.sort(key=lambda o: (o["kind"] != "Deployment", o["name"]))
        if ownership == "stopped":
            await self.repository.service(
                db,
                message.session_id,
                message.sandbox_id,
                now,
                self.settings.cleanup_seconds,
                objects,
            )
        elif ownership == "orphan":
            # Duplicate suggestions are harmless; advisory work locks plus UID preconditions
            # fence external effects. Persist only one outstanding exact-object intent.
            await db.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": str(message.sandbox_id)},
            )
            existing = await db.scalar(
                select(CleanupWork).where(
                    CleanupWork.kind == "orphan",
                    CleanupWork.sandbox_id == message.sandbox_id,
                )
            )
            if existing is None:
                db.add(
                    CleanupWork(
                        work_id=uuid4(),
                        session_id=None,
                        sandbox_id=message.sandbox_id,
                        pvc_id=None,
                        kind="orphan",
                        state_changed=now,
                        pvc_changed=None,
                        deadline=now + timedelta(seconds=self.settings.cleanup_seconds),
                        targets=objects,
                        acknowledged=True,
                        pair_snapshot=await self.repository.pair_snapshot(
                            db, message.session_id, message.sandbox_id
                        ),
                    )
                )

    @staticmethod
    def object_signal(obj: Object) -> Signal | None:
        try:
            meta = obj["metadata"]
            labels = meta["labels"]
            if any(key in labels for key in (GENERATION, PROJECT, "ads.io/egress-state-id")):
                # A wiped registry must not turn paired PVCs into legacy debris.
                # Their exact durable ledger, not label discovery, owns cleanup.
                return None
            sid, sandbox = UUID(labels[SESSION]), UUID(labels[SANDBOX])
            name, uid = meta["name"], meta["uid"]
            component = labels[COMPONENT]
            if obj["kind"] not in ("Deployment", "PersistentVolumeClaim") or not uid:
                return None
            if component == "ads-sandbox-ipc":
                valid = name == ipc_name(sandbox)
            elif component == CA_CONSUMER:
                valid = (
                    obj["kind"] == "PersistentVolumeClaim"
                    and name == ca_consumer_name(sandbox, labels[CA_CONSUMER_ROLE])
                    and not meta.get("ownerReferences")
                )
            elif component == "ads-sandbox":
                valid = (
                    name == session_name(sandbox)
                    if obj["kind"] == "Deployment"
                    else name == session_name(UUID(name.removeprefix("ads-sandbox-")))
                )
            else:
                return None
            return Signal(sid, sandbox, kind=obj["kind"], name=name, uid=uid) if valid else None
        except (KeyError, ValueError):
            return None

    async def scan(self, kind: str) -> None:
        now, s = datetime.now(UTC), self.settings
        signals: list[tuple[str, Signal]] = []
        if kind == "orphan":
            registry = PairRegistry(self.repository)
            async with self.sessions.begin() as db:
                generations = await registry.candidates(
                    db, s.lifecycle_batch, after=self._pair_scan_after
                )
            if generations:
                # Scheduling cursor only: proof and ownership remain durable.
                # A corrupt/blocked oldest page cannot starve unrelated pairs.
                self._pair_scan_after = generations[-1]
            for generation in generations:
                try:
                    async with self.sessions.begin() as db:
                        await registry.reconcile(db, generation, now, s.cleanup_seconds)
                except Exception:
                    log.warning("paired inventory reconciliation blocked: %s", generation)
            seen: set[UUID] = set()
            for obj in await self.kube.inventory():
                message = self.object_signal(obj)
                if message is None or message.sandbox_id in seen:
                    continue
                async with self.sessions.begin() as db:
                    if await self._ownership(db, message) == "owned":
                        continue
                seen.add(message.sandbox_id)
                signals.append((ORPHAN, message))
                if len(signals) == s.lifecycle_batch:
                    break
        else:
            async with self.sessions.begin() as db:
                if kind == "idle":
                    rows = await db.scalars(
                        select(SandboxSession)
                        .where(
                            SandboxSession.status == "ready",
                            SandboxSession.last_execution_at
                            <= now - timedelta(seconds=s.idle_seconds),
                        )
                        .order_by(SandboxSession.last_execution_at)
                        .limit(s.lifecycle_batch)
                    )
                    signals = [(IDLE, Signal(row.session_id, row.sandbox_id)) for row in rows]
                elif kind == "reap":
                    rows = await db.scalars(
                        select(SessionPVC)
                        .where(
                            SessionPVC.state == "detached",
                            SessionPVC.last_execution <= now - timedelta(seconds=s.idle_seconds),
                            SessionPVC.last_state_change
                            <= now - timedelta(seconds=s.detached_seconds),
                        )
                        .order_by(SessionPVC.last_state_change)
                        .limit(s.lifecycle_batch)
                    )
                    signals = [
                        (REAP, Signal(row.session_id, row.sandbox_id, row.pvc_id)) for row in rows
                    ]
                else:
                    rows = await db.scalars(
                        select(SessionPVC)
                        .where(
                            SessionPVC.state.in_(("attaching", "destroying")),
                            SessionPVC.last_state_change
                            <= now - timedelta(seconds=s.pvc_timeout_seconds),
                        )
                        .order_by(SessionPVC.last_state_change)
                        .limit(s.lifecycle_batch)
                    )
                    signals = [(RECOVER, Signal(row.session_id, row.sandbox_id)) for row in rows]
                    services = await db.scalars(
                        select(SandboxSession)
                        .where(
                            SandboxSession.status == "service",
                            SandboxSession.service_deadline <= now,
                        )
                        .limit(s.lifecycle_batch)
                    )
                    signals.extend(
                        (RECOVER, Signal(row.session_id, row.sandbox_id)) for row in services
                    )
                    create_seconds = max(
                        s.ready_seconds,
                        s.session_objects.create_seconds if s.session_objects else s.ready_seconds,
                    )
                    stalled = await db.scalars(
                        select(SandboxSession)
                        .where(
                            or_(
                                SandboxSession.status == "failed",
                                (
                                    SandboxSession.status.in_(("pending", "creating"))
                                    & (
                                        SandboxSession.status_changed_at
                                        <= now - timedelta(seconds=create_seconds)
                                    )
                                ),
                                (
                                    (SandboxSession.status == "recovering")
                                    & (
                                        SandboxSession.status_changed_at
                                        <= now - timedelta(seconds=s.recovery_seconds)
                                    )
                                ),
                            )
                        )
                        .order_by(SandboxSession.status_changed_at)
                        .limit(s.lifecycle_batch)
                    )
                    signals.extend(
                        (RECOVER, Signal(row.session_id, row.sandbox_id)) for row in stalled
                    )
        for topic, message in signals:
            await self.emit(topic, message)  # No outbox: unpublished observation loss is accepted.

    async def _save_targets(self, work: CleanupWork, targets: list[Object]) -> bool:
        async with self.sessions.begin() as db:
            if not await self.repository.owns(db, work):
                return False
            stored = await db.get(CleanupWork, work.work_id)
            if stored is None:
                return False
            stored.targets = targets
        work.targets = targets
        return True

    async def execute(self, work_id: UUID) -> None:
        async with self.sessions.begin() as db:
            work = await db.get(CleanupWork, work_id)
            if work is None or work.kind == "recovery" or not await self.repository.owns(db, work):
                return
            retained = await db.scalar(
                select(PairDisposal.generation).where(PairDisposal.work_id == work_id)
            )
            if work.kind == "orphan":
                # Rotate queue priority even for permanently ambiguous orphans.
                # This is scheduling only, never proof or an ambiguity timeout.
                work.deadline = datetime.now(UTC) + timedelta(seconds=self.settings.cleanup_seconds)
        if datetime.now(UTC) >= work.deadline:
            if work.kind == "idle" or retained is not None:
                async with self.sessions.begin() as db:
                    if not await self.repository.owns(db, work):
                        return
                    stored = await db.get(CleanupWork, work_id)
                    if stored is None:
                        return
                    stored.deadline = datetime.now(UTC) + timedelta(
                        seconds=self.settings.cleanup_seconds
                    )
                log.warning("idle cleanup overdue; retaining workspace and retrying: %s", work_id)
            elif work.session_id:
                await self.emit(RECOVER, Signal(work.session_id, work.sandbox_id))
                return
            # True orphans never recreate anything. Keep exact targets/evidence and retry.
        try:
            if retained is not None:
                if self.pair_resources is not None:
                    await PairRetainedDisposal(self.pair_resources).dispose(work)
                return
            if work.kind == "idle" and not work.acknowledged:
                async with asyncio.timeout(self.settings.control_seconds):
                    subject = await asyncio.to_thread(self.credentials.mint)
                    context = await asyncio.to_thread(self.tokens.mint, IPC, subject)
                    if not context.access_token:
                        raise RuntimeError("shutdown STE returned no token")
                    await self.publisher.send(
                        READY_TOPIC,
                        work.sandbox_id,
                        encode_ready(SandboxShutdown(work.sandbox_id, work.state_changed)),
                        context.access_token,
                    )
                return  # Teardown is impossible before the authenticated IPC drain ack.
            if work.pair_snapshot is not None:
                if work.kind in ("idle", "service", "reap", "orphan"):
                    if not await self.pair_capture.capture(work):
                        log.warning("paired writers unresolved; cleanup retained: %s", work_id)
                        return
                if self.pair_runtime is None or not await self.pair_runtime.release(work):
                    log.warning("pair retirement requires runtime-release proof: %s", work_id)
                    return
                await PairUnusedStorageTeardown(self.pair_runtime).dispose(work)
                if await PairIpcStorageTeardown(self.pair_runtime).dispose(work):
                    await PairBlockStorageTeardown(self.pair_runtime).dispose(work)
                if self.pair_resources is not None:
                    await self.pair_resources.dispose(work)
                async with self.sessions.begin() as db:
                    if work.kind == "idle":
                        await PairRetirementRepository(self.repository).finish_idle(
                            db, work, datetime.now(UTC)
                        )
                    else:
                        await PairRetirementRepository(self.repository).finish_destroyed(
                            db, work, datetime.now(UTC)
                        )
                return
            targets = []
            for obj in work.targets:
                # Retention keeps the idle release evidence after all Pods are gone.
                targets.append(obj if obj.get("captured") else await self.kube.capture(obj))
            if not await self._save_targets(work, targets):
                return
            # Also order persisted intents created by older manager versions.
            compute_pending = False
            for obj in sorted(targets, key=lambda t: t["kind"] != "Deployment"):
                if obj["kind"] != "Deployment" and compute_pending:
                    return
                async with self.sessions.begin() as db:
                    if not await self.repository.owns(db, work):
                        return
                    if work.kind == "orphan":
                        message = Signal(
                            UUID(obj["session_id"]),
                            UUID(obj["sandbox_id"]),
                            kind=obj["kind"],
                            name=obj["name"],
                            uid=obj["uid"],
                        )
                        if await self._ownership(db, message) != "orphan":
                            await db.delete(await db.get(CleanupWork, work.work_id))
                            return
                observed = await self.kube.observe(obj)
                if observed is None:
                    log.warning("cleanup exact target missing: %s uid=%s", obj["name"], obj["uid"])
                if obj["kind"] == "Deployment":
                    await self.kube.delete(obj)
                    observed = await self.kube.observe(obj)
                    if observed is not None and observed["metadata"]["uid"] == obj["uid"]:
                        compute_pending = True
                else:
                    if obj.get("retain") and (
                        observed is None or observed["metadata"]["uid"] != obj["uid"]
                    ):
                        return
                    if not await self.kube.released(obj):
                        return
                    if not obj.get("retain"):
                        await self.kube.delete(obj)
                        observed = await self.kube.observe(obj)
                        if observed is not None and observed["metadata"]["uid"] == obj["uid"]:
                            return
                        if not obj["name"].startswith(
                            "ads-sandbox-ipc-"
                        ) and not await self.kube.reclaimed(obj):
                            return
            if compute_pending:
                return
            async with self.sessions.begin() as db:
                await self.repository.complete(db, work, datetime.now(UTC))
        except Exception:
            if work.kind == "idle":
                log.warning("idle cleanup unavailable; workspace and intent retained: %s", work_id)
            elif work.session_id:
                await self.emit(RECOVER, Signal(work.session_id, work.sandbox_id))
            else:
                log.warning("orphan cleanup unavailable; exact target retained")

    async def _locked(self, key: str, operation: Callable[[], Awaitable[None]]) -> None:
        # The connection (not transaction) owns the advisory lock, released on crash.
        engine = self.sessions.kw["bind"]
        async with engine.connect() as connection:
            connection = await connection.execution_options(isolation_level="AUTOCOMMIT")
            locked = await connection.scalar(
                text("SELECT pg_try_advisory_lock(hashtextextended(:key, 0))"), {"key": key}
            )
            if not locked:
                return
            try:
                await operation()
            finally:
                await connection.execute(
                    text("SELECT pg_advisory_unlock(hashtextextended(:key, 0))"), {"key": key}
                )

    async def run_once(self) -> None:
        for kind in ("idle", "reap", "watchdog", "orphan"):
            await self._locked(f"manager-scheduler-{kind}", partial(self.scan, kind))
        async with self.sessions.begin() as db:
            ids = list(
                await db.scalars(
                    select(CleanupWork.work_id)
                    .where(
                        CleanupWork.kind != "recovery",
                    )
                    .order_by(CleanupWork.deadline)
                    .limit(self.settings.lifecycle_batch)
                )
            )
        for work_id in ids:
            await self._locked(str(work_id), partial(self.execute, work_id))

    async def _run(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                log.warning("manager lifecycle pass unavailable")
            await asyncio.sleep(self.settings.poll_seconds)

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="manager-lifecycle")
            self._ping_task = asyncio.create_task(self._ping_run(), name="manager-ipc-ping")

    async def _ping_run(self) -> None:
        while True:
            try:
                await self._locked("manager-scheduler-ping", self.ping_scan)
            except Exception:
                log.warning("manager ping pass unavailable")
            await asyncio.sleep(
                min(self.settings.poll_seconds, self.settings.ping_interval_seconds)
            )

    async def stop(self) -> None:
        if self._ping_task:
            self._ping_task.cancel()
            await asyncio.gather(self._ping_task, return_exceptions=True)
            self._ping_task = None
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
