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
from typing import Any, Protocol, cast
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.egress_state_objects import identity as egress_state_identity
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_compute import relay_input_name
from ads_sandbox_manager.pair_kube import ControlKind
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.pair_store import PairClaimLost
from ads_sandbox_manager.session_objects import ca_consumer_name, session_name
from ads_sandbox_manager.store import SandboxSession

log = logging.getLogger(__name__)


class PairTeardownKubernetes(Protocol):
    """Cleanup adapter surface; observed absence never authorizes recreation."""

    async def observe(self, target: Object) -> Object | None: ...
    async def delete(self, target: Object) -> None: ...
    async def observe_pod(self, name: str) -> Object | None: ...
    async def delete_pod(self, desired: Object, uid: str, *, node: str | None) -> bool: ...
    async def released(self, target: Object) -> bool: ...
    async def reclaimed(self, target: Object) -> bool: ...


class PairTeardownControls(Protocol):
    """Control-plane deleter surface (PairControlAdapter); absence-verified."""

    async def delete(self, pair: PairBinding, kind: ControlKind, role: str, uid: str) -> bool: ...
    async def dispose_secret(
        self,
        pair: PairBinding,
        key: str,
        uid: str,
        *,
        persistent: Object | None = None,
        retain: bool = False,
    ) -> bool: ...


class PairTeardown:
    """Thin ordered release replacing the journal-proof runtime teardown.

    Reuses the exact-target discipline: stored release evidence merged onto
    each target, UID-fenced observation, Foreground deletion, and
    released()/reclaimed() per object. Deletion never captures; evidence is
    consumed verbatim. Idle work stays gated on the authenticated IPC drain
    acknowledgement, which remains the hibernate boundary.
    """

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: LifecycleRepository,
        kube: PairTeardownKubernetes,
        controls: PairTeardownControls | None = None,
    ) -> None:
        self.settings = settings
        self.sessions = sessions
        self.repository = repository
        self.kube = kube
        self.controls = controls

    async def _owned(
        self, expected: CleanupWork, recovery: SandboxSession | None = None
    ) -> CleanupWork:
        """Re-read the exact same immutable claim; capture may have filled UIDs."""
        async with asyncio.timeout(self.settings.control_seconds):
            async with self.sessions.begin() as db:
                current = await db.get(CleanupWork, expected.work_id)
                if current is None:
                    raise PairClaimLost("paired teardown claim vanished")
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
            log.warning("paired teardown unavailable; exact targets retained", exc_info=True)
            return False

    @staticmethod
    def _secret_key(name: str, binding: PairBinding) -> str | None:
        """Classify a Secret target into a dispose_secret key, or None if unknown."""
        if name == f"ads-relay-keys-{binding.sandbox_id}.{binding.generation}":
            return "relay-custody"
        for role in ("guest-relay", "egress-relay"):
            if name == relay_input_name(binding, role):
                return f"relay-input/{role}"
        if name.startswith("ads-egress-key-"):
            return "state-key"
        return None

    async def _release(self, expected: CleanupWork, recovery: SandboxSession | None) -> bool:
        work = await self._owned(expected, recovery)
        snapshot = work.pair_snapshot
        if snapshot is None:
            # Orphan work carries no creator snapshot; its exact targets are
            # the scope and every object is revalidated below by uid or name.
            return await self._release_targets(work, None)
        return await self._release_targets(work, snapshot)

    async def _release_targets(self, work: CleanupWork, snapshot: dict[str, Any] | None) -> bool:
        # Pods first: ipc Pod (uid backfilled from the captured ownership),
        # then compute pods in fixed role order, each fenced by its exact UID.
        pod_uid = snapshot["ipc_resources"]["pod"]["uid"] if snapshot else None
        targets: list[tuple[Object, str | None]] = [
            (
                {"kind": "Pod", "name": obj["name"], "uid": obj["uid"] or pod_uid},
                obj["uid"] or pod_uid,
            )
            for obj in work.targets
            if obj["kind"] == "Pod" and (obj.get("uid") or pod_uid)
        ]
        if snapshot is not None:
            from ads_sandbox_manager.pair_objects import pair_name

            # Compute Pods are named pair_name(binding, role): ads-{role}-{sandbox}.
            binding = PairBinding(
                session_id=UUID(snapshot["session_id"]),
                sandbox_id=UUID(snapshot["sandbox_id"]),
                project_id=UUID(snapshot["project_id"]),
                generation=UUID(snapshot["generation"]),
            )
            for role in ("guest", "egress", "guest-relay", "egress-relay"):
                uid = snapshot["compute_uids"].get(f"Pod/{role}")
                if uid is None:
                    continue
                targets.append(({"kind": "Pod", "name": pair_name(binding, role), "uid": uid}, uid))
        for desired, uid in targets:
            assert uid is not None  # targets only exist with a UID
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
        if snapshot is not None:
            # Stored workspace identity rides on the intent entry, not the
            # carried target dict; merge it before any release check.
            workspace = snapshot["volume_resources"]["workspace"]
            evidence = workspace.get("release") if workspace.get("uid") else None
            if evidence:
                non_pods = [
                    {**obj, **evidence}
                    if obj["kind"] == "PersistentVolumeClaim"
                    and obj["name"] == session_name(UUID(snapshot["session_id"]))
                    else obj
                    for obj in non_pods
                ]
            # The retired generation owns its captured controls (PodGroups,
            # Services, NetworkPolicies) and CA clones until absence proves the
            # lifetime gone; a new generation's dispatch must never collide
            # with a stale label-fenced object. Keep carries the retained
            # workspace PVC and stays untouched. Relay custody/inputs and
            # egress-state key/volume are whole-lifetime secrets/storage.
            from ads_sandbox_manager.pair_objects import pair_name

            seen = {(obj["kind"], obj["name"]) for obj in non_pods}
            binding = PairBinding(
                session_id=UUID(snapshot["session_id"]),
                sandbox_id=UUID(snapshot["sandbox_id"]),
                project_id=UUID(snapshot["project_id"]),
                generation=UUID(snapshot["generation"]),
            )
            extra: list[dict[str, Any]] = []
            for key, uid in snapshot["control_uids"].items():
                if uid is None:
                    continue
                kind, role = key.split("/", 1)
                extra.append({"kind": kind, "name": pair_name(binding, role), "uid": uid})
            for role, entry in snapshot["volume_resources"].items():
                if role == "workspace" or not entry.get("uid"):
                    continue
                evidence = entry.get("release") or {}
                extra.append(
                    {
                        "kind": "PersistentVolumeClaim",
                        "name": ca_consumer_name(binding.sandbox_id, role),
                        "uid": entry["uid"],
                        **evidence,
                    }
                )
            custody = snapshot["relay_custody"]
            if custody.get("uid"):
                extra.append(
                    {
                        "kind": "Secret",
                        "name": f"ads-relay-keys-{binding.sandbox_id}.{binding.generation}",
                        "uid": custody["uid"],
                    }
                )
            for role, entry in snapshot["relay_inputs"].items():
                if entry.get("uid"):
                    extra.append(
                        {
                            "kind": "Secret",
                            "name": relay_input_name(binding, role),
                            "uid": entry["uid"],
                        }
                    )
            state_id = snapshot.get("egress_state_id")
            if state_id and work.kind != "idle":
                # Persistent state outlives only retained (idle) lifetimes;
                # destructive retirements delete the key and volume with it.
                async with self.sessions.begin() as db:
                    from ads_sandbox_manager.egress_state_store import EgressState

                    state = await db.get(EgressState, UUID(state_id))
                if state is not None:
                    for role, uid in (("key", state.key_uid), ("volume", state.volume_uid)):
                        if uid:
                            evidence = state.volume_release if role == "volume" else {}
                            extra.append(
                                {
                                    "kind": "Secret" if role == "key" else "PersistentVolumeClaim",
                                    "name": f"ads-egress-{role}-{state.state_id}",
                                    "uid": uid,
                                    **(evidence or {}),
                                }
                            )
            non_pods.extend(obj for obj in extra if (obj["kind"], obj["name"]) not in seen)
        # Control-plane objects (PodGroups, Services, NetworkPolicies) and
        # custody/inputs Secrets are deleted through the pair control adapter:
        # UID-fenced delete with observed absence as completion. The storage
        # released()/reclaimed() evidence below is CSI/PV-specific and can never
        # authorize a control or Secret; routing them there leaked them (and, for
        # PVCs missing capture evidence, wedged idle teardown entirely).
        # Controls for different kinds can share one object name (e.g. the
        # egress PodGroup and NetworkPolicy are both ads-egress-<sandbox>), so
        # identity is (kind, name), never name alone.
        # A snapshotless orphan has no creator identity to fence with; its exact
        # targets stay in the storage loop below, revalidated by their own uid.
        control_keys: dict[tuple[str, str], str] = {}
        if snapshot is not None:
            for ckey, cuid in snapshot["control_uids"].items():
                if cuid is None:
                    continue
                ckind, crole = ckey.split("/", 1)
                control_keys[(ckind, pair_name(binding, crole))] = ckey
        remaining: list[Object] = []
        for obj in non_pods:
            kind = obj["kind"]
            if snapshot is not None and kind in ("PodGroup", "Service", "NetworkPolicy"):
                key = control_keys.get((kind, obj["name"]))
                uid = obj.get("uid")
                if key is None or uid is None:
                    # A control without snapshot identity can never be fenced.
                    log.warning("unfenced pair control target retained: %s", obj["name"])
                    return False
                if self.controls is None:
                    log.warning("pair controls unavailable; target retained: %s", obj["name"])
                    return False
                ckind, crole = key.split("/", 1)
                # kind membership was checked above; snapshot keys are
                # ControlKind/role pairs, so ckind is always a ControlKind.
                if not await self.controls.delete(binding, cast(ControlKind, ckind), crole, uid):
                    return False
                continue
            if snapshot is not None and kind == "Secret":
                if self.controls is None:
                    log.warning("pair controls unavailable; target retained: %s", obj["name"])
                    return False
                uid = obj.get("uid")
                if not uid:
                    log.warning("unfenced pair secret target retained: %s", obj["name"])
                    return False
                key = self._secret_key(obj["name"], binding)
                if key is None:
                    log.warning("unknown pair secret target retained: %s", obj["name"])
                    return False
                persistent = None
                if key == "state-key":
                    # The state row outlives retained (idle) lifetimes, but its
                    # key object belongs to the dying generation: the next one
                    # re-issues it from the surviving row (HEAD parity).
                    state_id = snapshot.get("egress_state_id") if snapshot else None
                    if not state_id:
                        log.warning("state key without egress state retained: %s", obj["name"])
                        return False
                    async with self.sessions.begin() as db:
                        from ads_sandbox_manager.egress_state_store import EgressState

                        state = await db.get(EgressState, UUID(state_id))
                    if state is None:
                        log.warning("egress state row missing; key retained: %s", obj["name"])
                        return False
                    persistent = egress_state_identity(state, "key")
                if not await self.controls.dispose_secret(
                    binding, key, uid, persistent=persistent, retain=False
                ):
                    return False
                continue
            remaining.append(obj)
        non_pods = remaining
        # Stored release evidence only: capture happened while the pair was
        # alive (creation/ready-time or the paired cleanup capture), and this
        # path never derives evidence during deletion. A PVC without stored
        # identity stays bare and released() below fails closed, exactly as
        # designed for evidence-free or replaced claims.
        non_pods.sort(key=lambda t: t["kind"] != "Deployment")
        compute_pending = False
        for obj in non_pods:
            if obj["kind"] == "Deployment" and not obj.get("uid"):
                # Plain-column world: the guest runtime is raw Pods deleted by
                # captured UID above; a uid-less Deployment target is a legacy
                # row vestige that can never be fenced.
                continue
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
