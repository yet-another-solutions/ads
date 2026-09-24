"""Ordered private-compute release under existing lifecycle ownership."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime
from typing import Protocol

import msgspec
from kubernetes.client.exceptions import ApiException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_commons.sandbox.ipc_release import IpcReleaseReport, decode_ipc_release
from ads_commons.sandbox.node_release import NodeReleaseReport, decode_node_release
from ads_commons.sandbox.partial_release import PartialReleaseReport, decode_partial_release
from ads_sandbox_manager.cleanup import CleanupKubernetes
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES, PairBinding
from ads_sandbox_manager.pair_partial_proof import remaining_private
from ads_sandbox_manager.pair_storage_capture import storage_targets
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.pair_unscheduled_proof import RUNTIME_ROLES, never_scheduled, pod_uid
from ads_sandbox_manager.store import SandboxSession


class PairRuntimeKubernetes(Protocol):
    @property
    def namespace(self) -> str: ...
    @property
    def golden_version(self) -> str: ...
    async def compute_node(self, pair: PairBinding, uids: dict[str, str | None]) -> str: ...
    async def partial_node(self, pair: PairBinding, uids: dict[str, str]) -> str: ...
    async def delete_compute(
        self, pair: PairBinding, role: str, uid: str, *, node: str
    ) -> bool: ...
    async def ipc_placement(self, pair: PairBinding, uid: str) -> Object: ...
    async def delete_ipc(self, pair: PairBinding, uid: str, *, node: str) -> bool: ...
    async def unscheduled_pod(self, pair: PairBinding, role: str, uid: str) -> Object | None: ...
    async def delete_unscheduled(
        self, pair: PairBinding, role: str, captured: Object
    ) -> Object: ...


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
    async def capture_partial(
        self, pair: PairBinding, *, node: str, pod_uids: dict[str, str]
    ) -> bytes: ...
    async def observe_partial(self, captured: PartialReleaseReport) -> bytes: ...


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
        self._dispatches: set[asyncio.Task[None]] = set()

    def _finished(self, task: asyncio.Task[None]) -> None:
        self._dispatches.discard(task)
        if not task.cancelled():
            task.exception()  # Retrieve without logging private API/error bodies.

    async def drain(self) -> None:
        if self._dispatches:
            async with asyncio.timeout(self.settings.control_seconds):
                await asyncio.wait(tuple(self._dispatches))

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
        if (
            journal["node_capture"] is None
            and journal["ipc_capture"] is None
            and journal["partial_capture"] is None
            and await self._release_unscheduled(work, recovery)
        ):
            return True
        if self.node_owner is None:
            return False  # Unconfigured node delivery never authorizes runtime deletion.
        checkpoint = await self._checkpoint(work, recovery)
        if checkpoint is None:
            return False
        work, journal = checkpoint
        if journal["partial_capture"] is not None or any(
            self._never_started(journal, role) for role in RUNTIME_ROLES
        ):
            return await self._release_partial(work, recovery)
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

    @staticmethod
    def _never_started(journal: Object, role: str) -> bool:
        return f"Pod/{role}" in journal["runtime_unissued"] or never_scheduled(journal, role)

    async def _unscheduled_write(
        self, pair: PairBinding, role: str, index: int, captured: Object
    ) -> None:
        conflict, response = False, None
        try:
            async with asyncio.timeout(self.settings.control_seconds):
                response = await self.kube.delete_unscheduled(pair, role, captured)
        except ApiException as error:
            if error.status != 409:
                raise
            conflict = True  # Definitive rejection, not timeout/404/unknown completion.
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            await self.repository.settle_pair_unscheduled(
                db, pair, role, index, captured, response, conflict=conflict
            )

    async def _release_unscheduled(
        self, work: CleanupWork, recovery: SandboxSession | None
    ) -> bool:
        """Handle a prefix with no admitted runtime, preserving original writes."""
        candidates = {}
        pair = self.repository.cleanup_pair(work)
        for role in RUNTIME_ROLES:
            checkpoint = await self._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            if self._never_started(journal, role):
                continue
            attempts = journal["unscheduled"].get(role, [])
            if attempts and attempts[-1]["dispatch"] == "inflight":
                return False  # Original invocation may still be running; never replay.
            uid = pod_uid(journal["snapshot"], role)
            assert uid is not None  # A sealed dispatched writer has an exact original UID.
            async with asyncio.timeout(self.settings.control_seconds):
                observed = await self.kube.unscheduled_pod(pair, role, uid)
            if observed is not None:
                candidates[role] = observed
        # All remaining issued Pods were positively observed unassigned. Each
        # binding race is still fenced by its own original UID/resourceVersion.
        for role, captured in candidates.items():
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                work = await self._owned(db, work, recovery)
                index = await self.repository.reserve_pair_unscheduled(
                    db,
                    work,
                    role,
                    captured,
                    datetime.now(UTC),
                    recovery=recovery,
                    recovery_seconds=self.settings.recovery_seconds,
                )
            if index is not None:
                task = asyncio.create_task(
                    self._unscheduled_write(pair, role, index, captured),
                    name="pair-unscheduled-delete",
                )
                self._dispatches.add(task)
                task.add_done_callback(self._finished)
                await asyncio.wait((task,))  # Caller cancellation does not cancel the original.
                task.result()
            checkpoint = await self._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            if not self._never_started(journal, role):
                return False
        checkpoint = await self._checkpoint(work, recovery)
        return checkpoint is not None and all(
            self._never_started(checkpoint[1], role) for role in RUNTIME_ROLES
        )

    async def _release_partial(self, work: CleanupWork, recovery: SandboxSession | None) -> bool:
        """Compose never-started roles with exact assigned runtime proof.

        The observations retained here are not volume release/reclamation.
        Assigned IPC retains its separate application-node capture and release.
        """
        assert self.node_owner is not None
        checkpoint = await self._checkpoint(work, recovery)
        if checkpoint is None:
            return False
        work, journal = checkpoint
        if any(
            attempts and attempts[-1]["dispatch"] == "inflight"
            for attempts in journal["unscheduled"].values()
        ):
            return False
        if journal["partial_release"] is not None:
            return True
        pair = self.repository.cleanup_pair(work)
        uids = remaining_private(journal)
        for role, target in storage_targets(
            journal["snapshot"], journal["retain_workspace"], issued_only=True
        ).items():
            checkpoint = await self._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            if role in journal["partial_storage"]:
                continue
            async with asyncio.timeout(self.settings.control_seconds):
                evidence = await self.storage.capture(target)
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                work = await self._owned(db, work, recovery)
                await self.repository.record_pair_partial_storage(
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
        if uids and journal["partial_capture"] is None:
            async with asyncio.timeout(self.settings.control_seconds):
                node = await self.kube.partial_node(pair, uids)
            checkpoint = await self._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            async with asyncio.timeout(self.settings.control_seconds):
                raw = await self.node_owner.capture_partial(pair, node=node, pod_uids=uids)
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                work = await self._owned(db, work, recovery)
                if not await self.repository.record_pair_partial_proof(
                    db,
                    work,
                    raw,
                    datetime.now(UTC),
                    node=node,
                    network=self.node_owner.network,
                    recovery=recovery,
                    recovery_seconds=self.settings.recovery_seconds,
                ):
                    return False
        if not self._never_started(journal, "ipc") and not await self._release_ipc(work, recovery):
            return False
        if not uids:
            return True
        for role in COMPUTE_ROLES:
            if role not in uids:
                continue
            checkpoint = await self._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            captured = decode_partial_release(msgspec.json.encode(journal["partial_capture"]))
            async with asyncio.timeout(self.settings.control_seconds):
                if not await self.kube.delete_compute(pair, role, uids[role], node=captured.node):
                    return False
        checkpoint = await self._checkpoint(work, recovery)
        if checkpoint is None:
            return False
        work, journal = checkpoint
        captured = decode_partial_release(msgspec.json.encode(journal["partial_capture"]))
        async with asyncio.timeout(self.settings.control_seconds):
            raw = await self.node_owner.observe_partial(captured)
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            work = await self._owned(db, work, recovery)
            return await self.repository.record_pair_partial_proof(
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
