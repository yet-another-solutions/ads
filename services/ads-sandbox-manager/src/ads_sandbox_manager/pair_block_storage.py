"""Exact original Block disposition after runtime and kernel release."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import msgspec

from ads_commons.sandbox.block_release import decode_block_release
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_block_proof import CONSUMERS
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.store import SandboxSession


class PairBlockStorageTeardown:
    def __init__(self, runtime: PairRuntimeTeardown) -> None:
        self.runtime = runtime

    async def dispose(
        self, expected: CleanupWork, *, recovery: SandboxSession | None = None
    ) -> bool:
        r = self.runtime
        async with asyncio.timeout(r.settings.cleanup_seconds):
            checkpoint = await r._checkpoint(expected, recovery)
            if checkpoint is None or r.node_owner is None:
                return False
            work, journal = checkpoint
            if journal["block_capture"] is None or not (
                journal["runtime_release"] or journal["partial_release"]
            ):
                return False
            captured = decode_block_release(msgspec.json.encode(journal["block_capture"]))
            for role in CONSUMERS:
                if role not in captured.volumes:
                    continue
                checkpoint = await r._checkpoint(work, recovery)
                if checkpoint is None:
                    return False
                work, journal = checkpoint
                if role in journal["block_disposition"]:
                    continue
                target = {**journal["storage_capture"], **journal["partial_storage"]}[role]
                if not target["retain"] and not (
                    target["delete_policy"] and target["reclaim_guard"]
                ):
                    return False
                async with asyncio.timeout(r.settings.control_seconds):
                    raw = await r.node_owner.observe_block(captured)
                    if not await r.storage.released(target):
                        return False
                async with asyncio.timeout(r.settings.control_seconds), r.sessions.begin() as db:
                    work = await r._owned(db, work, recovery)
                    if not await r.repository.record_pair_block_proof(
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
                    obj = await r.storage.observe(target)
                    if obj is not None:
                        if obj["metadata"]["uid"] != target["uid"]:
                            raise RuntimeError("Block claim replacement refuses disposition")
                        current = await r.storage.capture(target)
                        if any(
                            current.get(key) != target[key]
                            for key in (
                                "pv_uid",
                                "pv_name",
                                "volume_key",
                                "delete_policy",
                                "reclaim_guard",
                            )
                        ):
                            raise RuntimeError("original Block backing changed")
                    elif target["retain"]:
                        raise RuntimeError("retained Block claim disappeared")
                checkpoint = await r._checkpoint(work, recovery)
                if checkpoint is None:
                    return False
                work, journal = checkpoint
                if not target["retain"]:
                    async with asyncio.timeout(r.settings.control_seconds):
                        await r.storage.delete(target)
                        if not await r.storage.reclaimed(target):
                            return False
                async with asyncio.timeout(r.settings.control_seconds), r.sessions.begin() as db:
                    work = await r._owned(db, work, recovery)
                    if not await r.repository.record_pair_block_disposition(
                        db,
                        work,
                        role,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=r.settings.recovery_seconds,
                    ):
                        return False
            return True
