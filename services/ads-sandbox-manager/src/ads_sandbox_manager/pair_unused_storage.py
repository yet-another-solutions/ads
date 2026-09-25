"""Dispose positively never-mounted claims without inventing node inventories."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID

import msgspec

from ads_commons.sandbox.block_release import decode_block_release
from ads_commons.sandbox.ipc_storage import decode_unused_ipc_storage
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_inherited_storage import inherited_capture
from ads_sandbox_manager.pair_resource_proof import runtime_complete
from ads_sandbox_manager.pair_retirement import PairRetirementRepository
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.pair_storage_capture import storage_targets
from ads_sandbox_manager.pair_unused_proof import unused_consumer
from ads_sandbox_manager.store import SandboxSession


class PairUnusedStorageTeardown:
    def __init__(self, runtime: PairRuntimeTeardown) -> None:
        self.runtime = runtime

    async def dispose(
        self, expected: CleanupWork, *, recovery: SandboxSession | None = None
    ) -> bool:
        r = self.runtime
        async with asyncio.timeout(r.settings.cleanup_seconds):
            checkpoint = await r._checkpoint(expected, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            if not runtime_complete(journal):
                return False
            targets = storage_targets(
                journal["snapshot"], journal["retain_workspace"], issued_only=True
            )
            for role, target in targets.items():
                consumer = unused_consumer(journal, role)
                if consumer is None:
                    continue
                checkpoint = await r._checkpoint(work, recovery)
                if checkpoint is None:
                    return False
                work, journal = checkpoint
                saved = journal["unused_storage"].get(role)
                if saved is not None and saved["disposition"] is not None:
                    continue
                if saved is None:
                    inherited = journal["snapshot"]["retained_from"] and role in (
                        "workspace",
                        "state",
                    )
                    if inherited:
                        async with r.sessions.begin() as db:
                            work = await r._owned(db, work, recovery)
                            previous = await PairRetirementRepository(r.repository).verify(
                                db, UUID(journal["snapshot"]["retained_from"])
                            )
                            evidence = inherited_capture(
                                previous, role, retain=journal["retain_workspace"]
                            )
                    else:
                        async with asyncio.timeout(r.settings.control_seconds):
                            evidence = await r.storage.capture_unused(
                                target,
                                unissued=consumer == "unissued",
                            )
                    async with asyncio.timeout(r.settings.control_seconds):
                        if evidence["mode"] == "never-mounted-filesystem":
                            if role != "ipc" or r.node_owner is None:
                                return False
                            raw = await r.node_owner.capture_unused_ipc_storage(
                                r.repository.cleanup_pair(work),
                                node=evidence["node"],
                                volume_uid=target["uid"],
                                pv_uid=evidence["target"]["pv_uid"],
                            )
                            evidence["backing"] = msgspec.to_builtins(
                                decode_unused_ipc_storage(raw)
                            )
                    async with (
                        asyncio.timeout(r.settings.control_seconds),
                        r.sessions.begin() as db,
                    ):
                        work = await r._owned(db, work, recovery)
                        if not await r.repository.record_pair_unused_storage(
                            db,
                            work,
                            role,
                            datetime.now(UTC),
                            captured=evidence,
                            recovery=recovery,
                            recovery_seconds=r.settings.recovery_seconds,
                        ):
                            return False
                checkpoint = await r._checkpoint(work, recovery)
                if checkpoint is None:
                    return False
                work, journal = checkpoint
                original = journal["unused_storage"][role]["capture"]
                filesystem = original["mode"] == "never-mounted-filesystem"
                if original["mode"] == "retired-inherited-csi" and not await self._inherited_proof(
                    work, recovery, role, original
                ):
                    return False
                if filesystem and not await self._filesystem_proof(work, recovery, role, original):
                    return False
                checkpoint = await r._checkpoint(work, recovery)
                if checkpoint is None:
                    return False
                work, journal = checkpoint
                async with asyncio.timeout(r.settings.control_seconds):
                    if not await r.storage.dispose_unused(
                        journal["unused_storage"][role]["capture"]
                    ):
                        return False
                if filesystem and not await self._filesystem_proof(
                    work, recovery, role, original, reclaimed=True
                ):
                    return False
                async with asyncio.timeout(r.settings.control_seconds), r.sessions.begin() as db:
                    work = await r._owned(db, work, recovery)
                    if not await r.repository.record_pair_unused_storage(
                        db,
                        work,
                        role,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=r.settings.recovery_seconds,
                    ):
                        return False
            return True

    async def _inherited_proof(
        self, work: CleanupWork, recovery: SandboxSession | None, role: str, original: Object
    ) -> bool:
        r = self.runtime
        captured = original["previous"]["block_capture"]
        if captured is None:
            return original["previous"]["never_mounted"] is True
        if r.node_owner is None:
            return False
        async with asyncio.timeout(r.settings.control_seconds):
            raw = await r.node_owner.observe_block(
                decode_block_release(msgspec.json.encode(captured))
            )
        if not decode_block_release(raw).released:
            return False
        async with r.sessions.begin() as db:
            work = await r._owned(db, work, recovery)
            return await r.repository.record_pair_unused_storage(
                db,
                work,
                role,
                datetime.now(UTC),
                proof=raw,
                recovery=recovery,
                recovery_seconds=r.settings.recovery_seconds,
            )

    async def _filesystem_proof(
        self,
        work: CleanupWork,
        recovery: SandboxSession | None,
        role: str,
        original: Object,
        *,
        reclaimed: bool = False,
    ) -> bool:
        r = self.runtime
        if r.node_owner is None:
            return False
        captured = decode_unused_ipc_storage(msgspec.json.encode(original["backing"]))
        async with asyncio.timeout(r.settings.control_seconds):
            raw = await r.node_owner.observe_unused_ipc_storage(captured)
        proof = decode_unused_ipc_storage(raw)
        if not proof.released or (reclaimed and not proof.reclaimed):
            return False
        async with r.sessions.begin() as db:
            work = await r._owned(db, work, recovery)
            return await r.repository.record_pair_unused_storage(
                db,
                work,
                role,
                datetime.now(UTC),
                proof=raw,
                recovery=recovery,
                recovery_seconds=r.settings.recovery_seconds,
            )
