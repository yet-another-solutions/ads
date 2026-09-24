"""Ordered private-compute release under existing lifecycle ownership."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime
from typing import Protocol

import msgspec
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_commons.sandbox.ipc_release import IpcReleaseReport, decode_ipc_release
from ads_commons.sandbox.node_release import NodeReleaseReport, decode_node_release
from ads_sandbox_manager.cleanup import CleanupKubernetes
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES, PairBinding
from ads_sandbox_manager.pair_storage_capture import storage_targets
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession


class PairRuntimeKubernetes(Protocol):
    @property
    def namespace(self) -> str: ...
    @property
    def golden_version(self) -> str: ...
    async def compute_node(self, pair: PairBinding, uids: dict[str, str | None]) -> str: ...
    async def delete_compute(
        self, pair: PairBinding, role: str, uid: str, *, node: str
    ) -> bool: ...
    async def ipc_placement(self, pair: PairBinding, uid: str) -> Object: ...
    async def delete_ipc(self, pair: PairBinding, uid: str, *, node: str) -> bool: ...


class PairNodeOwner(Protocol):
    """Trusted delivery port; no guest/relay-supplied report or success placeholder.

    Implementations must durably fence admission before capturing on the actual
    node. Reports are fresh responses over an authenticated node-owner channel.
    Host transport/partial-inventory integration is a separate component.
    """

    @property
    def network(self) -> str: ...
    async def fence_and_capture(self, pair: PairBinding, *, node: str) -> bytes: ...
    async def observe(self, captured: NodeReleaseReport) -> bytes: ...
    async def capture_ipc(
        self, pair: PairBinding, *, node: str, pod_uid: str, volume_uid: str
    ) -> bytes: ...
    async def observe_ipc(self, captured: IpcReleaseReport) -> bytes: ...


class PairRuntimeTeardown:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: LifecycleRepository,
        kube: PairRuntimeKubernetes,
        storage: CleanupKubernetes,
        node_owner: PairNodeOwner | None = None,
    ) -> None:
        self.settings, self.sessions, self.repository = settings, sessions, repository
        self.kube, self.storage, self.node_owner = kube, storage, node_owner

    async def _owned(
        self, db: AsyncSession, expected: CleanupWork, recovery: SandboxSession | None
    ) -> CleanupWork:
        # Capture may have filled unknown UIDs since the caller read the work.
        # Refresh only that same immutable claim, never a new work/session epoch.
        current = await db.get(CleanupWork, expected.work_id)
        fields = (
            "work_id",
            "session_id",
            "sandbox_id",
            "pvc_id",
            "kind",
            "state_changed",
            "pvc_changed",
            "targets",
        )
        if (
            current is None
            or any(getattr(current, field) != getattr(expected, field) for field in fields)
            or self.repository.cleanup_pair(current) != self.repository.cleanup_pair(expected)
        ):
            raise PairClaimLost("paired teardown claim changed")
        before, after = deepcopy(expected.pair_snapshot), current.pair_snapshot
        assert before is not None and after is not None
        for family in ("control_uids", "compute_uids"):
            for key, uid in before[family].items():
                if uid is None:
                    before[family][key] = after[family][key]
        for family in ("relay_inputs", "volume_resources", "ipc_resources"):
            for role, entry in before[family].items():
                if entry["uid"] is None:
                    entry["uid"] = after[family][role]["uid"]
        if before["relay_custody"]["uid"] is None:
            before["relay_custody"]["uid"] = after["relay_custody"]["uid"]
        if before["egress_state"] is not None and after["egress_state"] is not None:
            for role in ("key", "volume"):
                if before["egress_state"][f"{role}_uid"] is None:
                    before["egress_state"][f"{role}_uid"] = after["egress_state"][f"{role}_uid"]
        if before != after:
            raise PairClaimLost("paired teardown captured ownership changed")
        current = await self.repository.owned_pair_cleanup(
            db,
            current,
            datetime.now(UTC),
            recovery=recovery,
            recovery_seconds=self.settings.recovery_seconds,
        )
        if current.kind == "idle" and not current.acknowledged:
            raise PairClaimLost("IPC drain acknowledgement required before idle teardown")
        snapshot = current.pair_snapshot
        assert snapshot is not None
        wanted = self.settings.namespace, self.settings.golden_version
        if (self.kube.namespace, self.kube.golden_version) != wanted or (
            snapshot["namespace"],
            snapshot["golden_version"],
        ) != wanted:
            raise PairClaimLost("paired teardown configuration changed")
        return current

    async def _checkpoint(
        self, expected: CleanupWork, recovery: SandboxSession | None
    ) -> tuple[CleanupWork, Object] | None:
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            work = await self._owned(db, expected, recovery)
            if not await self.repository.seal_pair_cleanup(
                db,
                work,
                datetime.now(UTC),
                recovery=recovery,
                recovery_seconds=self.settings.recovery_seconds,
            ):
                return None
            pair = self.repository.cleanup_pair(work)
            intent = await db.get(PairIntent, pair.generation)
            assert intent is not None and intent.cleanup_journal is not None
            return work, deepcopy(intent.cleanup_journal)

    async def release(
        self, expected: CleanupWork, *, recovery: SandboxSession | None = None
    ) -> bool:
        async with asyncio.timeout(self.settings.cleanup_seconds):
            return await self._release(expected, recovery)

    async def _release(self, expected: CleanupWork, recovery: SandboxSession | None) -> bool:
        checkpoint = await self._checkpoint(expected, recovery)
        if checkpoint is None:
            return False
        work, journal = checkpoint
        if set(journal["runtime_unissued"]) == {
            *(f"Pod/{role}" for role in COMPUTE_ROLES),
            "Pod/ipc",
        }:
            # A sealed never-dispatched ledger is positive evidence that this
            # generation created no runtime. It is not an empty node report,
            # volume-release proof, deletion permit or retirement decision.
            return True
        if self.node_owner is None:
            return False  # Unconfigured node delivery never authorizes deletion.
        if journal["runtime_release"] is not None and journal["ipc_release"] is not None:
            return True  # Validated retained proof, not a fresh API-absence guess.
        pair = self.repository.cleanup_pair(work)
        for role, target in storage_targets(
            journal["snapshot"], journal["retain_workspace"]
        ).items():
            checkpoint = await self._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            if role in journal["storage_capture"]:
                continue
            async with asyncio.timeout(self.settings.control_seconds):
                evidence = await self.storage.capture(target)
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                work = await self._owned(db, work, recovery)
                await self.repository.record_pair_storage_capture(
                    db,
                    work,
                    role,
                    evidence,
                    datetime.now(UTC),
                    recovery=recovery,
                    recovery_seconds=self.settings.recovery_seconds,
                )
        checkpoint = await self._checkpoint(work, recovery)
        if checkpoint is None:
            return False
        work, journal = checkpoint
        if journal["node_capture"] is None:
            async with asyncio.timeout(self.settings.control_seconds):
                node = await self.kube.compute_node(pair, journal["snapshot"]["compute_uids"])
            # Placement I/O cannot carry a stale claim into node-side effects.
            checkpoint = await self._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            async with asyncio.timeout(self.settings.control_seconds):
                raw = await self.node_owner.fence_and_capture(pair, node=node)
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                work = await self._owned(db, work, recovery)
                await self.repository.record_pair_node_capture(
                    db,
                    work,
                    raw,
                    datetime.now(UTC),
                    node=node,
                    network=self.node_owner.network,
                    recovery=recovery,
                    recovery_seconds=self.settings.recovery_seconds,
                )
        if not await self._release_ipc(work, recovery):
            return False
        for role in COMPUTE_ROLES:
            checkpoint = await self._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            captured = decode_node_release(msgspec.json.encode(journal["node_capture"]))
            async with asyncio.timeout(self.settings.control_seconds):
                absent = await self.kube.delete_compute(
                    pair,
                    role,
                    journal["snapshot"]["compute_uids"][f"Pod/{role}"],
                    node=captured.node,
                )
            if not absent:
                return False
        checkpoint = await self._checkpoint(work, recovery)
        if checkpoint is None:
            return False
        work, journal = checkpoint
        captured = decode_node_release(msgspec.json.encode(journal["node_capture"]))
        async with asyncio.timeout(self.settings.control_seconds):
            raw = await self.node_owner.observe(captured)
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            work = await self._owned(db, work, recovery)
            return await self.repository.record_pair_runtime_release(
                db,
                work,
                raw,
                datetime.now(UTC),
                recovery=recovery,
                recovery_seconds=self.settings.recovery_seconds,
            )

    async def _release_ipc(self, work: CleanupWork, recovery: SandboxSession | None) -> bool:
        assert self.node_owner is not None
        checkpoint = await self._checkpoint(work, recovery)
        if checkpoint is None:
            return False
        work, journal = checkpoint
        if journal["ipc_release"] is not None:
            return True
        pair = self.repository.cleanup_pair(work)
        if journal["ipc_capture"] is None:
            resources = journal["snapshot"]["ipc_resources"]
            async with asyncio.timeout(self.settings.control_seconds):
                placement = await self.kube.ipc_placement(pair, resources["pod"]["uid"])
            checkpoint = await self._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            async with asyncio.timeout(self.settings.control_seconds):
                raw = await self.node_owner.capture_ipc(
                    pair,
                    node=placement["node"],
                    pod_uid=placement["uid"],
                    volume_uid=resources["volume"]["uid"],
                )
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                work = await self._owned(db, work, recovery)
                if not await self.repository.record_pair_ipc_proof(
                    db,
                    work,
                    raw,
                    datetime.now(UTC),
                    placement=placement,
                    recovery=recovery,
                    recovery_seconds=self.settings.recovery_seconds,
                ):
                    return False
        checkpoint = await self._checkpoint(work, recovery)
        if checkpoint is None:
            return False
        work, journal = checkpoint
        captured = decode_ipc_release(msgspec.json.encode(journal["ipc_capture"]))
        async with asyncio.timeout(self.settings.control_seconds):
            absent = await self.kube.delete_ipc(pair, str(captured.pod_uid), node=captured.node)
        if not absent:
            return False
        checkpoint = await self._checkpoint(work, recovery)
        if checkpoint is None:
            return False
        work, journal = checkpoint
        async with asyncio.timeout(self.settings.control_seconds):
            raw = await self.node_owner.observe_ipc(captured)
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            work = await self._owned(db, work, recovery)
            return await self.repository.record_pair_ipc_proof(
                db,
                work,
                raw,
                datetime.now(UTC),
                recovery=recovery,
                recovery_seconds=self.settings.recovery_seconds,
            )
