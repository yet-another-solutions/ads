from __future__ import annotations

import asyncio
import re
from copy import deepcopy
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from kubernetes.client.exceptions import ApiException
from kubernetes.utils.quantity import parse_quantity
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_commons.egress import SessionProjectsApi
from ads_sandbox_manager.ca import CaEnsure
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.golden import GoldenEnsure
from ads_sandbox_manager.kube import SessionKubernetes
from ads_sandbox_manager.objects import COMPONENT, JOB_UID, VERSION, Object
from ads_sandbox_manager.pair_creation import PairCreation
from ads_sandbox_manager.session_objects import (
    CA_CONSUMERS,
    SANDBOX,
    SESSION,
    ca_consumer_name,
    ca_consumer_pvc,
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
    async def remove(self, sandbox_id: UUID) -> bool: ...


class SessionBindError(RuntimeError):
    pass


class ClaimLost(RuntimeError):
    pass


_OMITTABLE_POD_LISTS = {
    ("spec", "template", "spec", "tolerations"),
    ("spec", "template", "spec", "imagePullSecrets"),
}


def contains(actual: object, expected: object, path: tuple[str, ...] = ()) -> bool:
    """Compare owned manifest fields while accepting API defaults and injected fields."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            (k in actual or (v == [] and (*path, k) in _OMITTABLE_POD_LISTS))
            and contains(actual.get(k), v, (*path, k))
            for k, v in expected.items()
        )
    if isinstance(expected, list):
        # The API omits these optional PodSpec lists when empty. This is not a
        # blanket missing-field allowance: nonempty policy and all other lists
        # (containers, volumes, capabilities, etc.) must still match exactly.
        if actual is None and not expected and path in _OMITTABLE_POD_LISTS:
            return True
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(contains(a, e, path) for a, e in zip(actual, expected, strict=True))
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
        projects: SessionProjectsApi,
        ca: CaEnsure | None = None,
        pair_creation: PairCreation | None = None,
    ) -> None:
        self.settings = settings
        self.kube = kube
        self.golden = golden
        self.sessions = sessions
        self.repository = repository
        self.topics = topics
        self.projects = projects
        self.ca = ca
        self.pair_creation = pair_creation

    async def drain(self) -> None:
        if self.pair_creation is not None:
            await self.pair_creation.drain()

    async def provision(self, session_id: UUID) -> SandboxSession:
        if not isinstance(session_id, UUID):
            raise ValueError("session_id must be a UUID")
        config = self.settings.session_objects
        if config is None:
            raise RuntimeError("session object configuration is required")
        owner = uuid4()
        # Resolve the ADS-owned association before creating any row or object.
        # Model/guest input and the delegated execution request cannot choose it.
        async with asyncio.timeout(self.settings.control_seconds):
            binding = await self.projects.session_project(session_id)
        if binding.session_id != session_id:
            raise SessionBindError("session project response mismatch")
        async with asyncio.timeout(config.create_seconds), self.sessions.begin() as db:
            inserted = await self.repository.insert_pending(
                db,
                session_id,
                uuid4(),
                self.settings.golden_version,
                datetime.now(UTC),
                binding.project_id,
            )
            row = await self.repository.get(db, session_id)
            assert row is not None
            if row.project_id != binding.project_id:
                raise SessionBindError("persisted session project changed")
            if not inserted and row.status != "stopped":
                return row
            resuming = row.status == "stopped" and row.pvc_id is not None
            claimed = await self.repository.claim(
                db, row, owner, datetime.now(UTC), paired=self.pair_creation is not None
            )
            if claimed is None:
                current = await self.repository.get(db, session_id)
                assert current is not None
                return current
            row = claimed
        return await self.build(row, resume=resuming)

    async def build(self, row: SandboxSession, *, resume: bool) -> SandboxSession:
        """Run an already committed, fenced creating claim, including recovery rebuilds."""
        config = self.settings.session_objects
        if config is None or row.claimed_by is None:
            raise RuntimeError("a configured provisioning claim is required")
        owner = row.claimed_by
        # No SQL transaction spans network I/O. Interruption leaves a durable
        # creating row; only the later watchdog/recover may take it over.
        try:
            async with asyncio.timeout(config.create_seconds):
                if self.pair_creation is not None:
                    return await self.pair_creation.build(row, resume=resume)
                if self.settings.pair_inputs is not None:
                    raise RuntimeError("configured paired runtime has no creation service")
                row = await self._disk(row, owner, resume=resume)
                row = await self._ca_disks(row, owner)
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
                await self._verify_ca(row)
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
                        row.ca_attempt,
                    ),
                    "guest_deployment_uid",
                )
                await self._verify_disk(row)
                await self._verify_ca(row)
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

    async def _ca_sources(self, row: SandboxSession) -> dict[str, Object]:
        if self.ca is None:
            raise SessionBindError("CA source service is required")
        sources = await self.ca.clone_sources()
        if sources is None:
            raise SessionBindError("CA output pair is not a safe clone source")
        attempts = {UUID(obj["metadata"]["labels"][JOB_UID]) for obj in sources.values()}
        if len(attempts) != 1 or (row.ca_attempt is not None and attempts != {row.ca_attempt}):
            raise SessionBindError("CA initialization attempt changed")
        identities = {role: obj["metadata"]["uid"] for role, obj in sources.items()}
        if row.ca_sources is not None and identities != row.ca_sources:
            raise SessionBindError("CA source identity changed")
        return sources

    def _ca_bind(self, row: SandboxSession, role: str, obj: Object, body: Object) -> str:
        meta, spec = obj.get("metadata", {}), obj.get("spec", {})
        previous = (row.ca_clones or {}).get(role)
        # Kubernetes mirrors a local dataSource into dataSourceRef. Nothing else,
        # especially cross-namespace references, is accepted.
        reference = spec.get("dataSourceRef")
        expected_ref = body["spec"]["dataSource"]
        # API quantity canonicalization (e.g. bytes -> Mi) and omitted core API
        # group are semantic defaults, not permission to accept a different source.
        comparable = deepcopy(obj)
        wanted_storage = body["spec"]["resources"]["requests"]["storage"]
        actual_storage = spec.get("resources", {}).get("requests", {}).get("storage", "0")
        same_size = parse_quantity(actual_storage) == parse_quantity(wanted_storage)
        if same_size:
            comparable["spec"]["resources"]["requests"]["storage"] = wanted_storage
        for key in ("dataSource", "dataSourceRef"):
            value = comparable.get("spec", {}).get(key)
            if isinstance(value, dict) and value.get("apiGroup") is None:
                value["apiGroup"] = ""
        reference = comparable.get("spec", {}).get("dataSourceRef")
        if (
            not meta.get("uid")
            or not meta.get("resourceVersion")
            or meta.get("deletionTimestamp")
            or meta.get("ownerReferences")
            or obj.get("status", {}).get("phase") == "Lost"
            or previous is not None
            and previous != meta["uid"]
            or reference is not None
            and reference != expected_ref
            or not same_size
            or not contains(comparable, body)
        ):
            raise SessionBindError("foreign, replaced, or incompatible CA clone")
        return str(meta["uid"])

    async def _ca_disks(self, row: SandboxSession, owner: UUID) -> SandboxSession:
        if self.settings.ca is None:
            return row  # Isolated component fixtures; runtime settings require CA.
        sources = await self._ca_sources(row)
        if row.ca_attempt is None:
            # Commit intent BEFORE the first create, including lost-response cleanup names.
            row = await self._record(
                row,
                owner,
                ca_attempt=UUID(sources["public"]["metadata"]["labels"][JOB_UID]),
                ca_sources={role: obj["metadata"]["uid"] for role, obj in sources.items()},
                ca_clones={},
            )
        for role, source_role in CA_CONSUMERS.items():
            row = await self._current(row, owner)
            sources = await self._ca_sources(row)
            body = ca_consumer_pvc(
                self.settings,
                row.session_id,
                row.sandbox_id,
                row.golden_version,
                role,
                sources[source_role],
            )
            obj = await self.kube.named_pvc(body["metadata"]["name"])
            if obj is None:
                if (row.ca_clones or {}).get(role):
                    raise SessionBindError("committed CA clone missing; recovery required")
                try:
                    await self.kube.create_pvc(body)
                except ApiException as exc:
                    if exc.status != 409:
                        raise
                obj = await self.kube.named_pvc(body["metadata"]["name"])
            if obj is None:
                raise SessionBindError("CA clone not observable after create")
            uid = self._ca_bind(row, role, obj, body)
            await self._ca_sources(row)  # Fence source replacement during CSI create.
            row = await self._record(row, owner, ca_clones={**(row.ca_clones or {}), role: uid})
        return row

    async def _verify_ca(self, row: SandboxSession) -> None:
        if self.settings.ca is None:
            return
        if row.ca_attempt is None or set(row.ca_clones or {}) != set(CA_CONSUMERS):
            raise SessionBindError("CA clones are not durably bound")
        sources = await self._ca_sources(row)
        for role, source_role in CA_CONSUMERS.items():
            obj = await self.kube.named_pvc(ca_consumer_name(row.sandbox_id, role))
            if obj is None:
                raise SessionBindError("CA clone missing before compute")
            self._ca_bind(
                row,
                role,
                obj,
                ca_consumer_pvc(
                    self.settings,
                    row.session_id,
                    row.sandbox_id,
                    row.golden_version,
                    role,
                    sources[source_role],
                ),
            )
