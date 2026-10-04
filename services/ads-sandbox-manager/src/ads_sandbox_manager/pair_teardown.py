"""Ordered pair teardown under existing lifecycle ownership; kube absence is terminal.

O2: no journal writes and no node-owner proofs. The drain ack gate still
precedes idle teardown; pods go first; every non-pod target must observe
as released (per the CSI-aware cleanup adapter) before its deletion, and
terminal state is positive kube API absence for all exact targets.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.cleanup import CleanupKubernetes
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_store import PairClaimLost
from ads_sandbox_manager.store import SandboxSession

log = logging.getLogger(__name__)


class PairTeardownKubernetes(Protocol):
    """Cleanup adapter surface; observed absence never authorizes recreation."""

    async def observe(self, target: Object) -> Object | None: ...
    async def delete(self, target: Object) -> None: ...
    async def observe_pod(self, name: str) -> Object | None: ...
    async def delete_pod(self, desired: Object, uid: str, *, node: str) -> bool: ...
    async def released(self, target: Object) -> bool: ...
    async def reclaimed(self, target: Object) -> bool: ...


class PairTeardown:
    """Thin ordered release replacing the journal-proof runtime teardown.

    Reuses the exact-target discipline of the legacy path: capture check,
    UID-fenced observation, Foreground deletion, and released()/reclaimed()
    evidence per object. Idle work stays gated on the authenticated IPC
    drain acknowledgement, which remains the hibernate boundary.
    """

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: LifecycleRepository,
        kube: PairTeardownKubernetes,
    ) -> None:
        self.settings = settings
        self.sessions = sessions
        self.repository = repository
        self.kube = kube

    async def _owned(
        self, expected: CleanupWork, recovery: SandboxSession | None = None
    ) -> CleanupWork:
        """Re-read the exact same immutable claim; capture may have filled UIDs."""
        async with asyncio.timeout(self.settings.control_seconds):
            async with self.sessions.begin() as db:
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
                snapshotless = current.pair_snapshot is None
                if snapshotless != (expected.pair_snapshot is None) or (
                    not snapshotless
                    and self.repository.cleanup_pair(current)
                    != self.repository.cleanup_pair(expected)
                ):
                    raise PairClaimLost("paired teardown claim changed")
                current = await self.repository.owned_pair_cleanup(
                    db,
                    current,
                    datetime.now(UTC),
                    recovery=recovery,
                    recovery_seconds=self.settings.recovery_seconds,
                )
                if current.kind == "idle" and not current.acknowledged:
                    raise PairClaimLost("IPC drain acknowledgement required before idle teardown")
                return current

    async def release(
        self, expected: CleanupWork, *, recovery: SandboxSession | None = None
    ) -> bool:
        """Release every exact target; True only when all show kube absence."""
        try:
            async with asyncio.timeout(self.settings.cleanup_seconds):
                return await self._release(expected, recovery)
        except PairClaimLost:
            raise
        except Exception:
            log.warning("paired teardown unavailable; exact targets retained")
            return False

    async def _release(
        self, expected: CleanupWork, recovery: SandboxSession | None
    ) -> bool:
        work = await self._owned(expected, recovery)
        snapshot = work.pair_snapshot
        if snapshot is None:
            # Orphan work carries no creator snapshot; its exact targets are
            # the scope and every object is revalidated below by uid or name.
            return await self._release_targets(work, None)
        return await self._release_targets(work, snapshot)

    async def _release_targets(
        self, work: CleanupWork, snapshot: dict[str, Any] | None
    ) -> bool:
        # Pods first: ipc Pod (uid backfilled from the captured ownership),
        # then compute pods in fixed role order, each fenced by its exact UID.
        pod_uid = snapshot["ipc_resources"]["pod"]["uid"] if snapshot else None
        targets: list[tuple[Object, str | None]] = [
            ({"kind": "Pod", "name": obj["name"], "uid": obj["uid"] or pod_uid}, obj["uid"] or pod_uid)
            for obj in work.targets
            if obj["kind"] == "Pod" and (obj.get("uid") or pod_uid)
        ]
        if snapshot is not None:
            for role in ("guest", "egress", "guest-relay", "egress-relay"):
                uid = snapshot["compute_uids"].get(f"Pod/{role}")
                if uid is None:
                    continue
                targets.append(
                    ({"kind": "Pod", "name": f"ads-sandbox-{role}-{work.sandbox_id}", "uid": uid}, uid)
                )
        for desired, uid in targets:
            observed = await self.kube.observe_pod(desired["name"])
            if observed is None:
                log.warning("cleanup exact target missing: %s uid=%s", desired["name"], uid)
                continue
            if observed["metadata"]["uid"] != uid:
                return False
            node = observed.get("spec", {}).get("nodeName")
            if not node:
                # Never-scheduled Pod: UID-fenced deletion without a node pin.
                if not await self.kube.delete_pod(observed, uid, node=None):
                    return False
                continue
            if not await self.kube.delete_pod(observed, uid, node=node):
                return False
        # Non-pods in existing Deployment-first order, exactly like the legacy path.
        non_pods = [obj for obj in work.targets if obj["kind"] != "Pod"]
        non_pods.sort(key=lambda t: t["kind"] != "Deployment")
        compute_pending = False
        for obj in non_pods:
            if obj["kind"] != "Deployment" and compute_pending:
                return False
            observed = await self.kube.observe(obj)
            if observed is None:
                log.warning("cleanup exact target missing: %s uid=%s", obj["name"], obj["uid"])
                if obj["kind"] == "Deployment":
                    compute_pending = True
                continue
            if obj["kind"] == "Deployment":
                await self.kube.delete(obj)
                observed = await self.kube.observe(obj)
                if observed is not None and observed["metadata"]["uid"] == obj["uid"]:
                    compute_pending = True
                continue
            if obj.get("retain") and (
                observed is None or observed["metadata"]["uid"] != obj["uid"]
            ):
                return False
            if not await self.kube.released(obj):
                return False
            if not obj.get("retain"):
                await self.kube.delete(obj)
                observed = await self.kube.observe(obj)
                if observed is not None and observed["metadata"]["uid"] == obj["uid"]:
                    return False
                if not obj["name"].startswith("ads-sandbox-ipc-") and not await self.kube.reclaimed(
                    obj
                ):
                    return False
        return not compute_pending
