from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Literal
from uuid import UUID, uuid4

import msgspec
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_commons.sandbox import SandboxShutdown, encode_ready
from ads_sandbox_manager.auth import IPC, ClientCredentials, TokenMinter
from ads_sandbox_manager.cleanup import CleanupKubernetes
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository, target
from ads_sandbox_manager.objects import COMPONENT, Object
from ads_sandbox_manager.service import READY_TOPIC, Publisher
from ads_sandbox_manager.session_objects import SANDBOX, SESSION, ipc_name, session_name
from ads_sandbox_manager.store import SandboxSession, SessionPVC

log = logging.getLogger(__name__)
IDLE = "ads.sandbox.idle"
REAP = "ads.sandbox.pvc.reap"
ORPHAN = "ads.sandbox.orphan"
RECOVER = "ads.sandbox.recover"
TOPICS = (IDLE, REAP, ORPHAN, RECOVER)


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
    ) -> None:
        self.settings, self.sessions, self.repository = settings, sessions, repository
        self.kube, self.publisher, self.credentials, self.tokens = (
            kube,
            publisher,
            credentials,
            tokens,
        )
        self._task: asyncio.Task[None] | None = None

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
                await r.recover(db, message.session_id, message.sandbox_id, now, s.cleanup_seconds)
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

    async def service_expired(self, row: SandboxSession) -> None:
        if row.service_deadline is not None and datetime.now(UTC) >= row.service_deadline:
            await self.emit(RECOVER, Signal(row.session_id, row.sandbox_id))

    async def _ownership(self, db: AsyncSession, message: Signal) -> str:
        row = await db.get(SandboxSession, message.session_id, with_for_update=True)
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
                    )
                )

    @staticmethod
    def object_signal(obj: Object) -> Signal | None:
        try:
            meta = obj["metadata"]
            labels = meta["labels"]
            sid, sandbox = UUID(labels[SESSION]), UUID(labels[SANDBOX])
            name, uid = meta["name"], meta["uid"]
            component = labels[COMPONENT]
            if obj["kind"] not in ("Deployment", "PersistentVolumeClaim") or not uid:
                return None
            if component == "ads-sandbox-ipc":
                valid = name == ipc_name(sandbox)
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
                            SessionPVC.state.in_(("attaching", "detaching", "destroying")),
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
        if datetime.now(UTC) >= work.deadline:
            if work.session_id:
                await self.emit(RECOVER, Signal(work.session_id, work.sandbox_id))
                return
            # True orphans never recreate anything. Keep exact targets/evidence and retry.
        try:
            if work.kind == "idle" and not work.acknowledged:
                async with asyncio.timeout(self.settings.control_seconds):
                    context = await asyncio.to_thread(self.tokens.mint, IPC)
                    if not context.access_token:
                        raise RuntimeError("shutdown STE returned no token")
                    await self.publisher.send(
                        READY_TOPIC,
                        work.sandbox_id,
                        encode_ready(SandboxShutdown(work.sandbox_id, work.state_changed)),
                        context.access_token,
                    )
                return  # Teardown is impossible before the authenticated IPC drain ack.
            targets = []
            for obj in work.targets:
                # Retention keeps the idle release evidence after all Pods are gone.
                targets.append(obj if obj.get("captured") else await self.kube.capture(obj))
            if not await self._save_targets(work, targets):
                return
            for obj in targets:
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
                        return
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
            async with self.sessions.begin() as db:
                await self.repository.complete(db, work, datetime.now(UTC))
        except Exception:
            if work.session_id:
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

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
