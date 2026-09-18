from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from kubernetes.client.exceptions import ApiException
from kubernetes.utils.quantity import parse_quantity
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.golden import GoldenEnsure
from ads_sandbox_manager.kube import SessionKubernetes
from ads_sandbox_manager.objects import COMPONENT, VERSION, Object
from ads_sandbox_manager.session_objects import (
    SANDBOX,
    SESSION,
    guest_deployment,
    ipc_deployment,
    ipc_pvc,
    session_name,
    session_pvc,
)
from ads_sandbox_manager.store import SandboxSession, SessionRepository


class TopicPreparation(Protocol):
    """Topics, local result subscription/seek, and best-effort replica barrier."""

    async def prepare(self, sandbox_id: UUID) -> None: ...


class SessionBindError(RuntimeError):
    pass


class ClaimLost(RuntimeError):
    pass


def contains(actual: object, expected: object) -> bool:
    """Compare owned manifest fields while accepting API defaults and injected fields."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            k in actual and contains(actual[k], v) for k, v in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(contains(a, e) for a, e in zip(actual, expected, strict=True))
        )
    return actual == expected


class SessionProvisioner:
    """Lifecycle worker called by authenticated transit with detached lifetime.

    A losing call returns durable status; it does not create or steal a worker.
    """

    def __init__(
        self,
        settings: Settings,
        kube: SessionKubernetes,
        golden: GoldenEnsure,
        sessions: async_sessionmaker[AsyncSession],
        repository: SessionRepository,
        topics: TopicPreparation,
    ) -> None:
        self.settings = settings
        self.kube = kube
        self.golden = golden
        self.sessions = sessions
        self.repository = repository
        self.topics = topics

    async def provision(self, session_id: UUID) -> SandboxSession:
        if not isinstance(session_id, UUID):
            raise ValueError("session_id must be a UUID")
        config = self.settings.session_objects
        if config is None:
            raise RuntimeError("session object configuration is required")
        owner = uuid4()
        async with asyncio.timeout(config.create_seconds), self.sessions.begin() as db:
            inserted = await self.repository.insert_pending(
                db,
                session_id,
                uuid4(),
                self.settings.golden_version,
                datetime.now(UTC),
            )
            row = await self.repository.get(db, session_id)
            assert row is not None
            if not inserted and row.status != "stopped":
                return row
            resuming = row.status == "stopped" and row.pvc_id is not None
            claimed = await self.repository.claim(db, row, owner, datetime.now(UTC))
            if claimed is None:
                current = await self.repository.get(db, session_id)
                assert current is not None
                return current
            row = claimed
        # No SQL transaction spans network I/O. Interruption leaves a durable
        # creating row; only the later watchdog/recover may take it over.
        try:
            async with asyncio.timeout(config.create_seconds):
                row = await self._disk(row, owner, resume=resuming)
                await self.topics.prepare(row.sandbox_id)
                row = await self._current(row, owner)
                row = await self._object(
                    row,
                    owner,
                    ipc_pvc(self.settings, row.session_id, row.sandbox_id, row.golden_version),
                    "ipc_pvc_uid",
                )
                # Re-GET the exact bind immediately before each compute create.
                await self._verify_disk(row)
                assert row.pvc_id is not None
                row = await self._object(
                    row,
                    owner,
                    guest_deployment(
                        self.settings,
                        row.session_id,
                        row.sandbox_id,
                        row.golden_version,
                        row.pvc_id,
                    ),
                    "guest_deployment_uid",
                )
                await self._verify_disk(row)
                return await self._object(
                    row,
                    owner,
                    ipc_deployment(
                        self.settings,
                        row.session_id,
                        row.sandbox_id,
                        row.golden_version,
                    ),
                    "ipc_deployment_uid",
                )
        except Exception:
            # Do not persist exception bodies: API/SQL errors may include credentials.
            async with asyncio.timeout(self.settings.control_seconds):
                await self._record(row, owner, status="failed", status_changed_at=datetime.now(UTC))
            raise

    async def _current(self, row: SandboxSession, owner: UUID) -> SandboxSession:
        async with self.sessions.begin() as db:
            current = await self.repository.owned(db, row, owner)
            if current is None:
                raise ClaimLost("session lifecycle claim changed")
            return current

    async def _record(
        self,
        row: SandboxSession,
        owner: UUID,
        **values: object,
    ) -> SandboxSession:
        async with self.sessions.begin() as db:
            current = await self.repository.record(db, row, owner, **values)
            if current is None:
                raise ClaimLost("session lifecycle claim changed")
            return current

    def _bind(self, row: SandboxSession, pvc: Object) -> str:
        assert row.pvc_id is not None
        meta, spec = pvc.get("metadata", {}), pvc.get("spec", {})
        labels = meta.get("labels", {})
        version = labels.get(VERSION, "")
        if (
            meta.get("name") != session_name(row.pvc_id)
            or meta.get("namespace") != self.settings.namespace
            or labels.get(SESSION) != str(row.session_id)
            or labels.get(SANDBOX) != str(row.sandbox_id)
            or labels.get(COMPONENT) != "ads-sandbox"
            or not meta.get("uid")
            or not meta.get("resourceVersion")
            or meta.get("deletionTimestamp")
            or meta.get("ownerReferences")
            or spec.get("volumeMode") != "Block"
            or spec.get("storageClassName") != "sandbox-block"
            or spec.get("accessModes") != ["ReadWriteOnce"]
            or pvc.get("status", {}).get("phase") == "Lost"
            or not re.fullmatch(
                r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?",
                version,
            )
        ):
            raise SessionBindError("foreign, deleting, or incompatible session PVC")
        if row.pvc_uid is not None and (
            meta["uid"] != row.pvc_uid or version != row.golden_version
        ):
            raise SessionBindError("session PVC identity changed; recovery required")
        return str(version)

    async def _verify_disk(self, row: SandboxSession) -> Object:
        assert row.pvc_id is not None
        pvc = await self.kube.named_pvc(session_name(row.pvc_id))
        if pvc is None:
            raise SessionBindError("session PVC missing; recovery required")
        self._bind(row, pvc)
        return pvc

    async def _disk(
        self,
        row: SandboxSession,
        owner: UUID,
        *,
        resume: bool,
    ) -> SandboxSession:
        row = await self._current(row, owner)
        if resume and row.pvc_uid is None:
            raise SessionBindError("resume has no durable PVC identity; recovery required")
        assert row.pvc_id is not None
        pvc = await self.kube.named_pvc(session_name(row.pvc_id))
        if row.pvc_uid is not None:
            if pvc is None:
                raise SessionBindError("session PVC missing; recovery required")
            self._bind(row, pvc)
            return row  # Resume NEVER clones, even if golden is unavailable.
        if pvc is None:
            if row.golden_version != self.settings.golden_version:
                raise SessionBindError("release golden is not a safe clone source")
            golden = await self.golden.clone_source()
            if golden is None:
                raise SessionBindError("release golden is not a safe clone source")
            storage = golden["spec"]["resources"]["requests"]["storage"]
            capacity = golden.get("status", {}).get("capacity", {}).get("storage", storage)
            # CSI destination must be at least the actual source capacity.
            storage = str(max(parse_quantity(storage), parse_quantity(capacity)))
            await self._current(row, owner)
            try:
                await self.kube.create_pvc(
                    session_pvc(
                        self.settings,
                        row.session_id,
                        row.sandbox_id,
                        row.golden_version,
                        storage,
                        row.pvc_id,
                    )
                )
            except ApiException as exc:
                if exc.status != 409:
                    raise
            pvc = await self.kube.named_pvc(session_name(row.pvc_id))
            if pvc is None:
                raise SessionBindError("session PVC not observable after create")
        version = self._bind(row, pvc)
        # This commit precedes topics and all compute: a crash cannot lose the bind.
        return await self._record(
            row,
            owner,
            pvc_uid=pvc["metadata"]["uid"],
            golden_version=version,
        )

    async def _object(
        self,
        row: SandboxSession,
        owner: UUID,
        body: Object,
        uid_field: str,
    ) -> SandboxSession:
        row = await self._current(row, owner)
        is_pvc = body["kind"] == "PersistentVolumeClaim"
        read = self.kube.named_pvc if is_pvc else self.kube.deployment
        create = self.kube.create_pvc if is_pvc else self.kube.create_deployment
        observed = await read(body["metadata"]["name"])
        if observed is None:
            try:
                await create(body)
            except ApiException as exc:
                if exc.status != 409:
                    raise
            observed = await read(body["metadata"]["name"])
        if observed is None:
            raise SessionBindError("session object not observable after create")
        meta = observed.get("metadata", {})
        spec = observed.get("spec", {})
        pod = spec.get("template", {}).get("spec", {})
        unsafe = (
            bool(spec.get("dataSource") or spec.get("dataSourceRef"))
            if is_pvc
            else (
                bool(spec.get("template", {}).get("metadata", {}).get("annotations"))
                or any(pod.get(key) for key in ("hostNetwork", "hostPID", "hostIPC"))
                or (
                    body["metadata"]["labels"]["app.kubernetes.io/component"] == "ads-sandbox-ipc"
                    and bool(pod.get("runtimeClassName"))
                )
            )
        )
        previous = getattr(row, uid_field)
        if (
            not meta.get("uid")
            or not meta.get("resourceVersion")
            or meta.get("deletionTimestamp")
            or meta.get("ownerReferences")
            or (previous is not None and previous != meta["uid"])
            or not contains(observed, body)
            or unsafe
        ):
            raise SessionBindError("foreign, replaced, or incompatible session object")
        return await self._record(row, owner, **{uid_field: meta["uid"]})
