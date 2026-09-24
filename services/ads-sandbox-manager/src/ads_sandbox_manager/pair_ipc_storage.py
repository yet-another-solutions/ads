"""Local IPC storage disposition under the original retained cleanup claim."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import msgspec

from ads_commons.sandbox.ipc_storage import decode_ipc_storage
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.store import SandboxSession


class PairIpcStorageTeardown:
    """Compose node filesystem proof with conservative Kubernetes blockers.

    This stage disposes only the original local IPC filesystem. It cannot
    dispose private Block volumes or authorize final generation retirement.
    """

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
            unused = journal["unused_storage"].get("ipc")
            if unused is not None and unused["disposition"] == "reclaimed":
                return True
            if r.node_owner is None:
                return False
            if journal["ipc_storage_reclaimed"] is not None:
                return True
            if journal["ipc_release"] is None or journal["ipc_storage_capture"] is None:
                return False
            target = journal["storage_capture"].get("ipc") or journal["partial_storage"].get("ipc")
            if not target or target["retain"] or "filesystem_backing" not in target:
                return False
            captured = decode_ipc_storage(msgspec.json.encode(journal["ipc_storage_capture"]))
            if journal["ipc_storage_release"] is None:
                async with asyncio.timeout(r.settings.control_seconds):
                    raw = await r.node_owner.observe_ipc_storage(captured)
                    # API/Node/VolumeAttachment checks only veto a positive node proof.
                    if not await r.storage.released(target):
                        return False
                async with asyncio.timeout(r.settings.control_seconds), r.sessions.begin() as db:
                    work = await r._owned(db, work, recovery)
                    if not await r.repository.record_pair_ipc_storage_observation(
                        db,
                        work,
                        raw,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=r.settings.recovery_seconds,
                    ):
                        return False
            checkpoint = await r._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            async with asyncio.timeout(r.settings.control_seconds):
                observed = await r.storage.observe(target)
                if observed is not None:
                    if observed["metadata"]["uid"] != target["uid"]:
                        raise RuntimeError("IPC storage replacement refuses cleanup")
                    current = await r.storage.capture(target)
                    for key in (
                        "pv_uid",
                        "pv_name",
                        "filesystem_backing",
                        "volume_key",
                        "delete_policy",
                    ):
                        if current.get(key) != target[key]:
                            raise RuntimeError("IPC storage backing changed before deletion")
            # No transaction spans API I/O. Revalidate after the read and before
            # the exact-UID/RV delete; retained identity survives a lost reply.
            checkpoint = await r._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            async with asyncio.timeout(r.settings.control_seconds):
                await r.storage.delete(target)
            checkpoint = await r._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            async with asyncio.timeout(r.settings.control_seconds):
                if await r.storage.observe(target) is not None:
                    return False
                raw = await r.node_owner.observe_ipc_storage(captured)
                if not await r.storage.released(target):
                    return False
            async with asyncio.timeout(r.settings.control_seconds), r.sessions.begin() as db:
                work = await r._owned(db, work, recovery)
                return await r.repository.record_pair_ipc_storage_observation(
                    db,
                    work,
                    raw,
                    datetime.now(UTC),
                    reclaimed=True,
                    recovery=recovery,
                    recovery_seconds=r.settings.recovery_seconds,
                )
