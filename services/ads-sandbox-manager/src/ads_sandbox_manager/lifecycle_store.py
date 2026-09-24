from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import msgspec
from sqlalchemy import DateTime, ForeignKey, delete, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_commons.sandbox.block_release import decode_block_release
from ads_commons.sandbox.ipc_release import decode_ipc_release
from ads_commons.sandbox.ipc_storage import decode_ipc_storage
from ads_commons.sandbox.node_release import decode_node_release
from ads_commons.sandbox.partial_release import decode_partial_release
from ads_sandbox_manager.egress_state_store import (
    EgressState,
    require_cleanup_state,
    state_from_snapshot,
    state_snapshot,
)
from ads_sandbox_manager.pair_block_proof import validate_block_journal
from ads_sandbox_manager.pair_compute_inputs import validate_compute_payloads
from ads_sandbox_manager.pair_ipc_inputs import ipc_role, validate_ipc_resources
from ads_sandbox_manager.pair_ipc_proof import ipc_capture_report, ipc_release_report
from ads_sandbox_manager.pair_node_proof import capture_report, release_report
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.pair_partial_proof import (
    partial_capture_report,
    partial_release_report,
    remaining_private,
    validate_partial_journal,
)
from ads_sandbox_manager.pair_resource_proof import resource_targets, validate_resource_journal
from ads_sandbox_manager.pair_storage_capture import (
    storage_targets,
    validate_storage_capture,
    validate_storage_observation,
)
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
from ads_sandbox_manager.pair_unscheduled_proof import (
    pod_uid,
    validate_observation,
    validate_unscheduled,
)
from ads_sandbox_manager.pair_volume_inputs import validate_volume_resources, volume_role
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
        target(
            "Pod" if row.ipc_pod_uid is not None else "Deployment",
            ipc_name(row.sandbox_id),
            row.ipc_pod_uid if row.ipc_pod_uid is not None else row.ipc_deployment_uid,
        ),
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
        validate_ipc_resources(intent.ipc_resources)
        validate_volume_resources(intent.volume_resources)
        validate_control_dispatch(intent)
        validate_compute_evidence(intent)
        if intent.topics_dispatch not in ("unissued", "inflight", "settled"):
            raise RuntimeError("corrupt paired topic dispatch")
        validate_relay_inputs(intent.binding(), intent.relay_inputs)
        persistent = None
        if intent.egress_state_id is not None:
            state = await db.get(
                EgressState,
                intent.egress_state_id,
                with_for_update=True,
                populate_existing=True,
            )
            if state is None or state.sandbox_id != intent.sandbox_id:
                raise RuntimeError("anchored persistent egress state missing")
            require_cleanup_state(state, intent)
            persistent = state_snapshot(state)
        current = {
            "generation": str(intent.generation),
            "session_id": str(intent.session_id),
            "sandbox_id": str(intent.sandbox_id),
            "project_id": str(intent.project_id),
            "claim_owner": str(intent.claim_owner),
            "claim_changed": intent.claim_changed.isoformat(),
            "namespace": intent.namespace,
            "golden_version": intent.golden_version,
            "control_uids": dict(intent.control_uids),
            "compute_uids": dict(intent.compute_uids),
            "control_dispatch": dict(intent.control_dispatch),
            "compute_dispatch": dict(intent.compute_dispatch),
            "compute_payloads": dict(intent.compute_payloads),
            "relay_custody": dict(intent.relay_custody),
            "relay_inputs": dict(intent.relay_inputs),
            "egress_state_id": str(intent.egress_state_id) if intent.egress_state_id else None,
            "egress_state": persistent,
            "ipc_resources": deepcopy(intent.ipc_resources),
            "volume_resources": deepcopy(intent.volume_resources),
            "topics_dispatch": intent.topics_dispatch,
        }
        return self.retained_pair_snapshot(intent, current)

    def retained_pair_snapshot(self, intent: PairIntent, current: dict[str, Any]) -> dict[str, Any]:
        """Recover original ownership, including UIDs captured after the creator lost its claim."""
        journal = intent.cleanup_journal
        if journal is None:
            return current
        if (
            not intent.creation_fenced
            or not isinstance(journal, dict)
            or set(journal)
            != {
                "snapshot",
                "creator_snapshot",
                "targets",
                "retain_workspace",
                "node_capture",
                "storage_capture",
                "runtime_release",
                "runtime_unissued",
                "ipc_placement",
                "ipc_capture",
                "ipc_release",
                "ipc_storage_capture",
                "ipc_storage_release",
                "ipc_storage_reclaimed",
                "unscheduled",
                "partial_storage",
                "partial_capture",
                "partial_release",
                "block_capture",
                "block_release",
                "block_disposition",
                "resource_disposition",
                "topic_disposition",
            }
            or type(journal["retain_workspace"]) is not bool
            or not isinstance(journal["targets"], list)
            or any(not isinstance(item, dict) for item in journal["targets"])
        ):
            raise RuntimeError("invalid retained pair cleanup journal")
        saved = journal["snapshot"]
        work = CleanupWork(
            sandbox_id=intent.sandbox_id, session_id=None, kind="orphan", pair_snapshot=saved
        )
        pair = self.cleanup_pair(work)
        if pair != intent.binding():
            raise PairClaimLost("retained cleanup pair identity changed")
        if current != journal["creator_snapshot"]:
            raise PairClaimLost("settled creator ledger changed after cleanup seal")
        if (
            any(item.get("retain") for item in journal["targets"])
            and not journal["retain_workspace"]
        ):
            raise RuntimeError("retained workspace disposition changed")
        # Original normal completion can settle a previously captured inflight
        # marker. A separately captured UID can fill a creator's unbound slot.
        # Neither exception permits replacing a known identity or erasing a write.
        comparable = deepcopy(current)

        def normalize(live: dict[str, Any], old: dict[str, Any], uid: str, dispatch: str) -> None:
            if live[uid] is None:
                live[uid] = old[uid]
            if (old[dispatch], live[dispatch]) == ("inflight", "settled"):
                live[dispatch] = old[dispatch]

        for family in ("control", "compute"):
            for key in comparable[f"{family}_uids"]:
                if comparable[f"{family}_uids"][key] is None:
                    comparable[f"{family}_uids"][key] = saved[f"{family}_uids"][key]
                if (
                    saved[f"{family}_dispatch"][key],
                    comparable[f"{family}_dispatch"][key],
                ) == ("inflight", "settled"):
                    comparable[f"{family}_dispatch"][key] = "inflight"
        for field in ("relay_inputs", "volume_resources", "ipc_resources"):
            for role, entry in comparable[field].items():
                normalize(entry, saved[field][role], "uid", "dispatch")
        normalize(comparable["relay_custody"], saved["relay_custody"], "uid", "dispatch")
        if comparable["egress_state"] is not None and saved["egress_state"] is not None:
            for role in ("key", "volume"):
                normalize(
                    comparable["egress_state"],
                    saved["egress_state"],
                    f"{role}_uid",
                    f"{role}_dispatch",
                )
        if (saved["topics_dispatch"], comparable["topics_dispatch"]) == ("inflight", "settled"):
            comparable["topics_dispatch"] = "inflight"
        if comparable != saved:
            raise PairClaimLost("retained cleanup ownership changed")
        if journal["runtime_unissued"] != self.unissued_runtime(saved):
            raise RuntimeError("retained never-dispatched runtime proof changed")
        if journal["runtime_unissued"] != self.unissued_runtime(current):
            raise PairClaimLost("creator never-dispatched runtime proof changed")
        validate_unscheduled(saved, journal["unscheduled"])
        validate_partial_journal(journal, pair)
        if not isinstance(journal["storage_capture"], dict):
            raise RuntimeError("invalid retained storage capture")
        if journal["storage_capture"]:
            targets = storage_targets(saved, journal["retain_workspace"])
            for role, evidence in journal["storage_capture"].items():
                if role not in targets:
                    raise RuntimeError("foreign retained storage capture")
                validate_storage_capture(targets[role], evidence, filesystem=role == "ipc")
        self.validate_ipc_journal(journal, pair)
        if journal["node_capture"] is not None:
            raw = msgspec.json.encode(journal["node_capture"])
            report = decode_node_release(raw)
            capture_report(
                raw,
                pair,
                node=report.node,
                namespace=saved["namespace"],
                network=report.network,
                pod_uids=saved["compute_uids"],
            )
        if journal["runtime_release"] is not None:
            if journal["node_capture"] is None or set(journal["storage_capture"]) != set(
                storage_targets(saved, journal["retain_workspace"])
            ):
                raise RuntimeError("runtime release missing original capture")
            if not release_report(
                msgspec.json.encode(journal["runtime_release"]),
                decode_node_release(msgspec.json.encode(journal["node_capture"])),
            ):
                raise RuntimeError("retained runtime report does not prove release")
        validate_block_journal(journal)
        validate_resource_journal(journal)
        return deepcopy(saved)

    @staticmethod
    def unissued_runtime(snapshot: dict[str, Any]) -> list[str]:
        """Classify a sealed creator ledger, not an API or kernel inventory.

        This becomes proof only inside a validated retained journal, after the
        permanent creator fence and settlement of every original writer. A null
        UID alone says nothing about whether a Pod could have started.
        """
        result = [
            key
            for key, dispatch in sorted(snapshot["compute_dispatch"].items())
            if dispatch == "unissued" and snapshot["compute_uids"][key] is None
        ]
        ipc = snapshot["ipc_resources"]["pod"]
        if ipc["dispatch"] == "unissued" and ipc["uid"] is None and ipc["payload"] is None:
            result.append("Pod/ipc")
        return result

    @staticmethod
    def validate_ipc_journal(journal: dict[str, Any], pair: PairBinding) -> None:
        placement, captured = journal["ipc_placement"], journal["ipc_capture"]
        saved = journal["snapshot"]
        if placement is not None:
            if (
                not isinstance(placement, dict)
                or set(placement) != {"uid", "node", "resource_version"}
                or any(not isinstance(v, str) or not v.strip() for v in placement.values())
                or placement["uid"] != saved["ipc_resources"]["pod"]["uid"]
            ):
                raise RuntimeError("invalid original IPC placement")
        if captured is not None:
            storage = journal["storage_capture"].get("ipc") or journal["partial_storage"].get("ipc")
            if placement is None or storage is None:
                raise RuntimeError("IPC capture missing original placement or storage")
            if placement["node"] not in storage["nodes"]:
                raise RuntimeError("IPC node differs from captured volume use")
            ipc_capture_report(
                msgspec.json.encode(captured),
                pair,
                node=placement["node"],
                namespace=saved["namespace"],
                pod_uid=placement["uid"],
                volume_uid=saved["ipc_resources"]["volume"]["uid"],
            )
        if journal["ipc_release"] is not None:
            if captured is None or not ipc_release_report(
                msgspec.json.encode(journal["ipc_release"]),
                decode_ipc_release(msgspec.json.encode(captured)),
            ):
                raise RuntimeError("retained IPC report does not prove release")
        backing = journal["ipc_storage_capture"]
        storage = journal["storage_capture"].get("ipc") or journal["partial_storage"].get("ipc")
        if (
            storage is not None
            and "filesystem_backing" in storage
            and journal["ipc_release"] is not None
            and backing is None
        ):
            raise RuntimeError("IPC release lacks original backing capture")
        if backing is not None:
            report = decode_ipc_storage(msgspec.json.encode(backing))
            storage = journal["storage_capture"].get("ipc") or journal["partial_storage"].get("ipc")
            if captured is None or storage is None or "filesystem_backing" not in storage:
                raise RuntimeError("IPC backing capture lacks original runtime/storage")
            if (
                report.observed
                or str(report.pv_uid) != storage["pv_uid"]
                or report.runtime_sha256 != captured["inventory_sha256"]
                or any(
                    backing[key] != captured[key]
                    for key in (
                        "node",
                        "namespace",
                        "generation",
                        "sandbox_id",
                        "boot_id",
                        "pod_uid",
                        "volume_uid",
                    )
                )
            ):
                raise RuntimeError("IPC backing capture identity changed")
        for phase in ("release", "reclaimed"):
            proof = journal[f"ipc_storage_{phase}"]
            if proof is None:
                continue
            report = decode_ipc_storage(msgspec.json.encode(proof))
            if (
                backing is None
                or journal["ipc_release"] is None
                or not report.observed
                or not report.released
                or (phase == "reclaimed" and not report.reclaimed)
                or any(
                    proof[key] != backing[key]
                    for key in backing
                    if key not in ("observed", "released", "reclaimed")
                )
                or (phase == "reclaimed" and journal["ipc_storage_release"] is None)
            ):
                raise RuntimeError("IPC storage observation lacks original positive proof")

    async def seal_pair_cleanup(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        """Persist complete captured ownership outside the cascading work row.

        The caller commits before any node call or deletion. This is not a
        runtime-release verdict, deletion permit, or generation retirement.
        """
        if not await self.pair_writers_settled(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        pair = self.cleanup_pair(expected)
        assert expected.pair_snapshot is not None
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None
        if intent.cleanup_journal is None:
            creator_snapshot = await self.pair_snapshot(db, pair.session_id, pair.sandbox_id)
            intent.cleanup_journal = {
                "snapshot": deepcopy(expected.pair_snapshot),
                "creator_snapshot": creator_snapshot,
                "targets": deepcopy(expected.targets),
                "retain_workspace": expected.kind == "idle"
                or any(item.get("retain") for item in expected.targets),
                "node_capture": None,
                "storage_capture": {},
                "runtime_release": None,
                "runtime_unissued": self.unissued_runtime(expected.pair_snapshot),
                "ipc_placement": None,
                "ipc_capture": None,
                "ipc_release": None,
                "ipc_storage_capture": None,
                "ipc_storage_release": None,
                "ipc_storage_reclaimed": None,
                "unscheduled": {},
                "partial_storage": {},
                "partial_capture": None,
                "partial_release": None,
                "block_capture": None,
                "block_release": None,
                "block_disposition": {},
                "resource_disposition": {},
                "topic_disposition": None,
            }
            await db.flush()
        retained = await self.pair_snapshot(db, pair.session_id, pair.sandbox_id)
        if retained != expected.pair_snapshot:
            raise PairClaimLost("cleanup claim differs from retained ownership")
        return True

    async def reserve_pair_unscheduled(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        role: str,
        captured: dict[str, Any],
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> int | None:
        """Commit original conditional deletion before its only invocation.

        A direct deleting/unscheduled observation excludes future admission.
        Otherwise only the original DELETE response can settle this operation.
        Neither a 404 nor expiry is permission to replay an inflight DELETE.
        """
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            raise PairClaimLost("pair writers have not settled")
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = deepcopy(intent.cleanup_journal)
        validate_observation(captured, pod_uid(journal["snapshot"], role))
        attempts = journal["unscheduled"].setdefault(role, [])
        if attempts and attempts[-1]["dispatch"] != "conflict":
            return None  # Existing original invocation or positive terminal proof.
        if len(attempts) >= 128:
            raise PairClaimLost("unscheduled conflict history exhausted; intent retained")
        observed = captured["deletion_timestamp"] is not None
        attempts.append(
            {
                "capture": deepcopy(captured),
                "dispatch": "observed" if observed else "inflight",
                "response": None,
            }
        )
        validate_unscheduled(journal["snapshot"], journal["unscheduled"])
        intent.cleanup_journal = journal
        await db.flush()
        return None if observed else len(attempts) - 1

    async def settle_pair_unscheduled(
        self,
        db: AsyncSession,
        pair: PairBinding,
        role: str,
        index: int,
        captured: dict[str, Any],
        response: dict[str, Any] | None,
        *,
        conflict: bool = False,
    ) -> None:
        """Save the original call's outcome even after caller/claim loss.

        No new deletion is authorized here. The retained exact reservation is
        required and cannot be recreated, replaced or reassigned to a new pair.
        A normal HTTP 409 is a rejected operation; other failures stay inflight.
        """
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        if intent is None or intent.binding() != pair or intent.cleanup_journal is None:
            raise PairClaimLost("original unscheduled cleanup intent missing")
        # Validate the permanent fence, creator seal and entire prior proof.
        await self.pair_snapshot(db, pair.session_id, pair.sandbox_id)
        journal = deepcopy(intent.cleanup_journal)
        attempts = journal["unscheduled"].get(role, [])
        if type(index) is not int or index != len(attempts) - 1 or index < 0:
            raise PairClaimLost("original unscheduled dispatch missing")
        original = attempts[index]
        outcome = {
            "capture": deepcopy(captured),
            "dispatch": "conflict" if conflict else "settled",
            "response": deepcopy(response),
        }
        if original["capture"] != captured or original["dispatch"] not in (
            "inflight",
            outcome["dispatch"],
        ):
            raise PairClaimLost("original unscheduled dispatch changed")
        if original["dispatch"] != "inflight" and original != outcome:
            raise PairClaimLost("original unscheduled outcome cannot be replaced")
        attempts[index] = outcome
        validate_unscheduled(journal["snapshot"], journal["unscheduled"])
        intent.cleanup_journal = journal
        await db.flush()

    async def record_pair_partial_storage(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        role: str,
        evidence: dict[str, Any],
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> None:
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            raise PairClaimLost("pair writers have not settled")
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = deepcopy(intent.cleanup_journal)
        targets = storage_targets(
            journal["snapshot"], journal["retain_workspace"], issued_only=True
        )
        if role not in targets:
            raise ValueError("unsupported original partial storage role")
        validate_storage_observation(targets[role], evidence)
        old = journal["partial_storage"].get(role)
        if old is not None and old != evidence:
            raise PairClaimLost("original partial storage observation cannot be replaced")
        journal["partial_storage"][role] = deepcopy(evidence)
        validate_partial_journal(journal, pair)
        intent.cleanup_journal = journal
        await db.flush()

    async def record_pair_partial_proof(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        raw: bytes,
        now: datetime,
        *,
        node: str | None = None,
        network: str | None = None,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = deepcopy(intent.cleanup_journal)
        if journal["node_capture"] is not None:
            raise PairClaimLost("full node capture cannot be replaced by partial proof")
        report = decode_partial_release(raw)
        value = msgspec.to_builtins(report)
        if node is not None:
            if network is None:
                raise ValueError("trusted partial network required")
            partial_capture_report(
                raw,
                pair,
                node=node,
                network=network,
                namespace=journal["snapshot"]["namespace"],
                pod_uids=remaining_private(journal),
            )
            field = "partial_capture"
        else:
            if journal["partial_capture"] is None:
                raise PairClaimLost("original partial capture required")
            if not partial_release_report(
                raw, decode_partial_release(msgspec.json.encode(journal["partial_capture"]))
            ):
                return False
            field = "partial_release"
        if journal[field] is not None and journal[field] != value:
            raise PairClaimLost("original partial proof cannot be replaced")
        journal[field] = value
        validate_partial_journal(journal, pair)
        intent.cleanup_journal = journal
        await db.flush()
        return True

    async def record_pair_node_capture(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        raw: bytes,
        now: datetime,
        *,
        node: str,
        network: str,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> None:
        """Bind a trusted node response after rechecking the original cleanup claim.

        The caller supplies fresh trusted placement and node-owner transport.
        No transport, freshness, or deletion authority is manufactured here.
        """
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            raise PairClaimLost("pair writers have not settled")
        pair = self.cleanup_pair(expected)
        snapshot = expected.pair_snapshot
        assert snapshot is not None
        report = capture_report(
            raw,
            pair,
            node=node,
            namespace=snapshot["namespace"],
            network=network,
            pod_uids=snapshot["compute_uids"],
        )
        value = msgspec.to_builtins(report)
        value["pod_uids"] = sorted(value["pod_uids"])
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = intent.cleanup_journal
        if journal["node_capture"] is not None and journal["node_capture"] != value:
            raise PairClaimLost("original node capture cannot be replaced")
        intent.cleanup_journal = {**journal, "node_capture": value}
        await db.flush()

    async def record_pair_storage_capture(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        role: str,
        evidence: dict[str, Any],
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> None:
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            raise PairClaimLost("pair writers have not settled")
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = intent.cleanup_journal
        targets = storage_targets(journal["snapshot"], journal["retain_workspace"])
        if role not in targets:
            raise ValueError("unsupported paired storage role")
        validate_storage_capture(targets[role], evidence, filesystem=role == "ipc")
        saved = journal["storage_capture"]
        if role in saved and saved[role] != evidence:
            raise PairClaimLost("original storage capture cannot be replaced")
        intent.cleanup_journal = {**journal, "storage_capture": {**saved, role: deepcopy(evidence)}}
        await db.flush()

    async def record_pair_runtime_release(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        raw: bytes,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        """Persist positive original-inventory proof, never API-absence inference."""
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = intent.cleanup_journal
        if journal["node_capture"] is None or set(journal["storage_capture"]) != set(
            storage_targets(journal["snapshot"], journal["retain_workspace"])
        ):
            raise PairClaimLost("original node and storage captures required")
        captured = decode_node_release(msgspec.json.encode(journal["node_capture"]))
        if not release_report(raw, captured):
            return False
        value = msgspec.to_builtins(decode_node_release(raw))
        value["pod_uids"] = sorted(value["pod_uids"])
        if journal["runtime_release"] is not None and journal["runtime_release"] != value:
            raise PairClaimLost("original runtime-release report cannot be replaced")
        intent.cleanup_journal = {**journal, "runtime_release": value}
        await db.flush()
        return True

    async def record_pair_ipc_proof(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        raw: bytes,
        now: datetime,
        *,
        placement: dict[str, Any] | None = None,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        """Commit original capture or positive observation under the same cleanup claim."""
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = deepcopy(intent.cleanup_journal)
        value = msgspec.to_builtins(decode_ipc_release(raw))
        if placement is not None:
            if journal["ipc_placement"] is not None and journal["ipc_placement"] != placement:
                raise PairClaimLost("original IPC placement cannot be replaced")
            if journal["ipc_capture"] is not None and journal["ipc_capture"] != value:
                raise PairClaimLost("original IPC capture cannot be replaced")
            journal.update(ipc_placement=deepcopy(placement), ipc_capture=value)
        else:
            if journal["ipc_capture"] is None:
                raise PairClaimLost("original IPC capture required")
            if not ipc_release_report(
                raw, decode_ipc_release(msgspec.json.encode(journal["ipc_capture"]))
            ):
                return False
            if journal["ipc_release"] is not None and journal["ipc_release"] != value:
                raise PairClaimLost("original IPC release cannot be replaced")
            journal["ipc_release"] = value
        self.validate_ipc_journal(journal, pair)
        intent.cleanup_journal = journal
        await db.flush()
        return True

    async def record_pair_ipc_storage_capture(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        raw: bytes,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = deepcopy(intent.cleanup_journal)
        value = msgspec.to_builtins(decode_ipc_storage(raw))
        if journal["ipc_storage_capture"] is not None and journal["ipc_storage_capture"] != value:
            raise PairClaimLost("original IPC backing capture cannot be replaced")
        journal["ipc_storage_capture"] = value
        self.validate_ipc_journal(journal, pair)
        intent.cleanup_journal = journal
        await db.flush()
        return True

    async def record_pair_ipc_storage_observation(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        raw: bytes,
        now: datetime,
        *,
        reclaimed: bool = False,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = deepcopy(intent.cleanup_journal)
        report = decode_ipc_storage(raw)
        # Validate scope before accepting even a blocked observer response.
        value = msgspec.to_builtins(report)
        captured = journal["ipc_storage_capture"]
        if (
            captured is None
            or any(
                value[key] != captured[key]
                for key in captured
                if key not in ("observed", "released", "reclaimed")
            )
            or not report.observed
        ):
            raise PairClaimLost("original IPC backing observation required")
        if not report.released or (reclaimed and not report.reclaimed):
            return False
        key = "ipc_storage_reclaimed" if reclaimed else "ipc_storage_release"
        if journal[key] is not None:
            # A later observation may progress from released to reclaimed.
            # Keep the original positive receipt; never rewrite its identity.
            self.validate_ipc_journal(journal, pair)
            return True
        journal[key] = value
        self.validate_ipc_journal(journal, pair)
        intent.cleanup_journal = journal
        await db.flush()
        return True

    async def record_pair_block_proof(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        raw: bytes,
        now: datetime,
        *,
        capture: bool = False,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = deepcopy(intent.cleanup_journal)
        report = decode_block_release(raw)
        value = msgspec.to_builtins(report)
        key = "block_capture" if capture else "block_release"
        if not capture:
            original = journal["block_capture"]
            if original is None or any(
                value[k] != original[k] for k in original if k not in ("leftovers", "released")
            ):
                raise PairClaimLost("original Block observation binding changed")
            if not report.released:
                return False
        if journal[key] is not None and journal[key] != value:
            raise PairClaimLost("original Block receipt cannot be replaced")
        journal[key] = value
        validate_block_journal(journal)
        intent.cleanup_journal = journal
        await db.flush()
        return True

    async def record_pair_block_disposition(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        role: str,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = deepcopy(intent.cleanup_journal)
        target = {**journal["storage_capture"], **journal["partial_storage"]}[role]
        journal["block_disposition"][role] = "retained" if target["retain"] else "reclaimed"
        validate_block_journal(journal)
        intent.cleanup_journal = journal
        await db.flush()
        return True

    async def record_pair_resource_disposition(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        key: str,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        if not await self.seal_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        ):
            return False
        pair = self.cleanup_pair(expected)
        intent = await db.get(PairIntent, pair.generation, with_for_update=True)
        assert intent is not None and intent.cleanup_journal is not None
        journal = deepcopy(intent.cleanup_journal)
        if key == "topics":
            journal["topic_disposition"] = (
                "unissued"
                if journal["snapshot"]["topics_dispatch"] == "unissued"
                else "retained"
                if journal["retain_workspace"]
                else "deleted"
            )
        else:
            journal["resource_disposition"][key] = resource_targets(journal)[key]
        validate_resource_journal(journal)
        intent.cleanup_journal = journal
        await db.flush()
        return True

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
        snapshot = await self.pair_snapshot(db, row.session_id, row.sandbox_id)
        if row.ipc_pod_uid is not None and snapshot is None:
            raise RuntimeError("paired IPC Pod has no retained generation ownership")
        if snapshot is not None:
            if row.ipc_pod_uid is not None and (
                row.ipc_pod_uid != snapshot["ipc_resources"]["pod"]["uid"]
            ):
                raise RuntimeError("paired IPC Pod session identity changed")
            targets = [
                {**obj, "kind": "Pod", "uid": snapshot["ipc_resources"]["pod"]["uid"]}
                if obj["name"] == ipc_name(row.sandbox_id) and obj["kind"] in ("Deployment", "Pod")
                else obj
                for obj in targets
            ]
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
            pair_snapshot=snapshot,
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
            "claim_owner",
            "claim_changed",
            "namespace",
            "golden_version",
            "control_uids",
            "compute_uids",
            "control_dispatch",
            "compute_dispatch",
            "relay_custody",
            "relay_inputs",
            "compute_payloads",
            "egress_state_id",
            "egress_state",
            "ipc_resources",
            "volume_resources",
            "topics_dispatch",
        }
        if not isinstance(snapshot, dict) or set(snapshot) != fields:
            raise RuntimeError("incomplete pair cleanup snapshot")
        try:
            owner, changed = snapshot["claim_owner"], snapshot["claim_changed"]
            if not isinstance(owner, str) or str(UUID(owner)) != owner:
                raise ValueError
            if not isinstance(changed, str):
                raise ValueError
            instant = datetime.fromisoformat(changed)
            if instant.tzinfo is None or instant.isoformat() != changed:
                raise ValueError
        except ValueError:
            raise RuntimeError("invalid captured pair creator claim") from None
        for family, keys in (
            ("control", {resource_key(*item) for item in CONTROL_RESOURCES}),
            ("compute", set(new_compute_uids())),
        ):
            dispatches = snapshot[f"{family}_dispatch"]
            if (
                not isinstance(dispatches, dict)
                or set(dispatches) != keys
                or any(
                    value not in ("unissued", "inflight", "settled")
                    for value in dispatches.values()
                )
            ):
                raise RuntimeError("corrupt captured pair dispatch")
        validate_relay_custody(snapshot["relay_custody"])
        validate_ipc_resources(snapshot["ipc_resources"])
        validate_volume_resources(snapshot["volume_resources"])
        if snapshot["topics_dispatch"] not in ("unissued", "inflight", "settled"):
            raise RuntimeError("corrupt paired topic cleanup evidence")
        state_id = snapshot["egress_state_id"]
        if state_id is not None and (
            not isinstance(state_id, str) or str(UUID(state_id)) != state_id
        ):
            raise RuntimeError("invalid persistent egress cleanup anchor")
        persistent = snapshot["egress_state"]
        if (state_id is None) != (persistent is None):
            raise RuntimeError("persistent egress cleanup anchor and snapshot disagree")
        if persistent is not None:
            state = state_from_snapshot(persistent)
            if (
                str(state.state_id) != state_id
                or str(state.sandbox_id) != snapshot["sandbox_id"]
                or str(state.session_id) != snapshot["session_id"]
                or str(state.project_id) != snapshot["project_id"]
                or str(state.creator_generation) != snapshot["generation"]
                or state.namespace != snapshot["namespace"]
                or state.sandbox_id != work.sandbox_id
            ):
                raise RuntimeError("persistent egress cleanup state identity changed")
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
            or str(intent.claim_owner) != work.pair_snapshot["claim_owner"]
            or intent.claim_changed.isoformat() != work.pair_snapshot["claim_changed"]
        ):
            raise PairClaimLost("pair creator fence identity changed")
        validate_control_dispatch(intent)
        validate_compute_evidence(intent)
        validate_relay_custody(intent.relay_custody)
        validate_relay_inputs(intent.binding(), intent.relay_inputs)
        validate_compute_payloads(intent.compute_payloads)
        validate_ipc_resources(intent.ipc_resources)
        validate_volume_resources(intent.volume_resources)
        if intent.topics_dispatch != work.pair_snapshot["topics_dispatch"] and (
            work.pair_snapshot["topics_dispatch"],
            intent.topics_dispatch,
        ) != ("inflight", "settled"):
            raise PairClaimLost("paired topic cleanup ownership changed")
        for role, entry in intent.volume_resources.items():
            captured = work.pair_snapshot["volume_resources"][role]
            if (
                entry["payload"] != captured["payload"]
                or (entry["uid"] is not None and entry["uid"] != captured["uid"])
                or (
                    entry["dispatch"] != captured["dispatch"]
                    and (captured["dispatch"], entry["dispatch"]) != ("inflight", "settled")
                )
            ):
                raise PairClaimLost("paired clone cleanup ownership changed")
        for role, entry in intent.ipc_resources.items():
            captured = work.pair_snapshot["ipc_resources"][role]
            if (
                entry["payload"] != captured["payload"]
                or (entry["uid"] is not None and entry["uid"] != captured["uid"])
                or (
                    entry["dispatch"] != captured["dispatch"]
                    and (captured["dispatch"], entry["dispatch"]) != ("inflight", "settled")
                )
            ):
                raise PairClaimLost("paired IPC cleanup ownership changed")
        state_id = str(intent.egress_state_id) if intent.egress_state_id else None
        if state_id != work.pair_snapshot["egress_state_id"]:
            raise PairClaimLost("persistent egress cleanup anchor changed")
        if intent.egress_state_id is not None:
            state = await db.get(
                EgressState,
                intent.egress_state_id,
                with_for_update=True,
                populate_existing=True,
            )
            if state is None:
                raise PairClaimLost("persistent egress cleanup reservation missing")
            require_cleanup_state(
                state, intent, state_from_snapshot(work.pair_snapshot["egress_state"])
            )
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

    async def pair_writers_settled(
        self,
        db: AsyncSession,
        expected: CleanupWork,
        now: datetime,
        *,
        recovery: SandboxSession | None = None,
        recovery_seconds: float = 0,
    ) -> bool:
        """Fence future dispatch and check every original writer under the claim.

        A normal return settled by the original publisher is the only positive
        write evidence. Captured UIDs cannot settle an ambiguous invocation.
        This neither proves runtime release nor authorizes resource deletion.
        """
        work = await self.owned_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        )
        intent = await self.fence_pair_creators(db, work)
        snapshot = work.pair_snapshot
        assert snapshot is not None and intent.creation_fenced
        evidence: list[tuple[str, str | None]] = []
        for family in ("control", "compute"):
            for key, dispatch in getattr(intent, f"{family}_dispatch").items():
                before = snapshot[f"{family}_dispatch"][key]
                uid = getattr(intent, f"{family}_uids")[key]
                if (dispatch != before and (before, dispatch) != ("inflight", "settled")) or (
                    uid is not None and uid != snapshot[f"{family}_uids"][key]
                ):
                    # Metadata capture still preserves the original obligation;
                    # later ledger drift cannot establish positive settlement.
                    return False
            evidence.extend(
                (dispatch, snapshot[f"{family}_uids"][key])
                for key, dispatch in getattr(intent, f"{family}_dispatch").items()
            )
        for field in ("relay_inputs", "volume_resources", "ipc_resources"):
            for role, entry in getattr(intent, field).items():
                captured = snapshot[field][role]
                before = captured["dispatch"]
                if entry["dispatch"] != before and (before, entry["dispatch"]) != (
                    "inflight",
                    "settled",
                ):
                    raise PairClaimLost("pair cleanup resource dispatch changed")
                if entry["uid"] is not None and entry["uid"] != captured["uid"]:
                    raise PairClaimLost("pair cleanup resource identity changed")
                evidence.append((entry["dispatch"], captured["uid"]))
        custody, captured = intent.relay_custody, snapshot["relay_custody"]
        if (
            custody["dispatch"] != captured["dispatch"]
            and (captured["dispatch"], custody["dispatch"]) != ("inflight", "settled")
        ) or (custody["uid"] is not None and custody["uid"] != captured["uid"]):
            raise PairClaimLost("pair cleanup custody evidence changed")
        evidence.append((custody["dispatch"], captured["uid"]))
        if intent.egress_state_id is not None:
            state = await db.get(
                EgressState, intent.egress_state_id, with_for_update=True, populate_existing=True
            )
            assert state is not None  # Already validated and locked by the creator fence.
            evidence.extend(
                (getattr(state, f"{role}_dispatch"), snapshot["egress_state"][f"{role}_uid"])
                for role in ("key", "volume")
            )
        return intent.topics_dispatch != "inflight" and all(
            (dispatch == "unissued" and uid is None) or (dispatch == "settled" and uid is not None)
            for dispatch, uid in evidence
        )

    async def record_clone(
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
        volume_role(role)
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid paired clone cleanup UID")
        work = await self.owned_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        )
        await self.fence_pair_creators(db, work)
        assert work.pair_snapshot is not None
        resources = work.pair_snapshot["volume_resources"]
        entry = resources[role]
        if entry["dispatch"] == "unissued":
            raise RuntimeError("paired clone was never dispatched")
        if uid is not None:
            if entry["uid"] is not None and entry["uid"] != uid:
                raise RuntimeError("paired clone cleanup UID replacement refused")
            work.pair_snapshot = {
                **work.pair_snapshot,
                "volume_resources": {
                    **resources,
                    role: {**entry, "uid": uid},
                },
            }
            await db.flush()
        return work

    async def record_ipc_resource(
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
        ipc_role(role)
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid paired IPC cleanup UID")
        work = await self.owned_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        )
        await self.fence_pair_creators(db, work)
        assert work.pair_snapshot is not None
        resources = work.pair_snapshot["ipc_resources"]
        entry = resources[role]
        if entry["dispatch"] == "unissued":
            raise RuntimeError("paired IPC resource was never dispatched")
        if uid is not None:
            if entry["uid"] is not None and entry["uid"] != uid:
                raise RuntimeError("paired IPC cleanup UID replacement refused")
            work.pair_snapshot = {
                **work.pair_snapshot,
                "ipc_resources": {**resources, role: {**entry, "uid": uid}},
            }
            await db.flush()
        return work

    async def record_egress_state(
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
        """Capture only named Secret/PVC metadata; never key data or absence."""
        if role not in ("key", "volume"):
            raise ValueError("unsupported persistent egress cleanup role")
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid persistent egress cleanup UID")
        work = await self.owned_pair_cleanup(
            db, expected, now, recovery=recovery, recovery_seconds=recovery_seconds
        )
        await self.fence_pair_creators(db, work)
        assert work.pair_snapshot is not None
        persistent = work.pair_snapshot["egress_state"]
        if persistent is None:
            raise RuntimeError("persistent egress state was never reserved")
        state = state_from_snapshot(persistent)
        if getattr(state, f"{role}_dispatch") == "unissued":
            raise RuntimeError("persistent egress resource was never dispatched")
        if uid is not None:
            previous = getattr(state, f"{role}_uid")
            if previous is not None and previous != uid:
                raise RuntimeError("persistent egress cleanup UID replacement refused")
            persistent = {**persistent, f"{role}_uid": uid}
            state_from_snapshot(persistent)
            work.pair_snapshot = {**work.pair_snapshot, "egress_state": persistent}
            await db.flush()
        return work

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
            if row.ipc_pod_uid is not None:
                return False  # Never retire untracked paired Pod ownership through legacy cleanup.
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
        row.ipc_pod_uid = None  # Original exact Pod remains in the committed cleanup snapshot.
        row.ca_attempt = row.ca_sources = row.ca_clones = None
        row.last_ping_at = row.last_ping_sent_at = None
        await db.execute(delete(PingProbe).where(PingProbe.sandbox_id == sandbox_id))
        if pvc:
            pvc.state = "failed"
            pvc.last_state_change = advance(pvc.last_state_change, now)
        return True
