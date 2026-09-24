"""Dispose positively never-mounted claims without inventing node inventories."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_resource_proof import runtime_complete
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
                    async with asyncio.timeout(r.settings.control_seconds):
                        evidence = await r.storage.capture_unused(
                            target,
                            unissued=consumer == "unissued",
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
                async with asyncio.timeout(r.settings.control_seconds):
                    if not await r.storage.dispose_unused(
                        journal["unused_storage"][role]["capture"]
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
