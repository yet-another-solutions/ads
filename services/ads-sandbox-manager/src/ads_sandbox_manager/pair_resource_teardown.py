"""Exact control, transient-custody and topic disposition after all users stop."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import UUID

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_kube import ControlKind
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.pair_resource_proof import (
    resource_targets,
    runtime_complete,
    storage_complete,
)
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.store import SandboxSession


class ResourceKubernetes(Protocol):
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


class ResourceTopics(Protocol):
    async def remove(self, sandbox_id: UUID) -> bool: ...


class PairResourceTeardown:
    def __init__(
        self, runtime: PairRuntimeTeardown, kube: ResourceKubernetes, topics: ResourceTopics
    ) -> None:
        self.runtime, self.kube, self.topics = runtime, kube, topics

    async def dispose(
        self, expected: CleanupWork, *, recovery: SandboxSession | None = None
    ) -> bool:
        r = self.runtime
        async with asyncio.timeout(r.settings.cleanup_seconds):
            checkpoint = await r._checkpoint(expected, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            if not runtime_complete(journal) or not storage_complete(journal):
                return False
            targets = resource_targets(journal)
            # Keep NetworkPolicies through runtime AND storage release. Their
            # order here cannot bypass those original-journal gates.
            for key, target in targets.items():
                checkpoint = await r._checkpoint(work, recovery)
                if checkpoint is None:
                    return False
                work, journal = checkpoint
                if key in journal["resource_disposition"]:
                    continue
                pair = r.repository.cleanup_pair(work)
                async with asyncio.timeout(r.settings.control_seconds):
                    if key.startswith("control/"):
                        _, kind, role = key.split("/")
                        done = await self.kube.delete(
                            pair,
                            cast(ControlKind, kind),
                            role,
                            target["uid"],
                        )
                    else:
                        done = await self.kube.dispose_secret(
                            pair,
                            key,
                            target["uid"],
                            persistent=journal["snapshot"]["egress_state"],
                            retain=target["disposition"] == "retained",
                        )
                if not done:
                    return False
                async with asyncio.timeout(r.settings.control_seconds), r.sessions.begin() as db:
                    work = await r._owned(db, work, recovery)
                    if not await r.repository.record_pair_resource_disposition(
                        db,
                        work,
                        key,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=r.settings.recovery_seconds,
                    ):
                        return False
            checkpoint = await r._checkpoint(work, recovery)
            if checkpoint is None:
                return False
            work, journal = checkpoint
            if journal["topic_disposition"] is not None:
                return True
            if (
                journal["snapshot"]["topics_dispatch"] != "unissued"
                and not journal["retain_workspace"]
            ):
                async with asyncio.timeout(r.settings.control_seconds):
                    if not await self.topics.remove(work.sandbox_id):
                        return False
            async with asyncio.timeout(r.settings.control_seconds), r.sessions.begin() as db:
                work = await r._owned(db, work, recovery)
                return await r.repository.record_pair_resource_disposition(
                    db,
                    work,
                    "topics",
                    datetime.now(UTC),
                    recovery=recovery,
                    recovery_seconds=r.settings.recovery_seconds,
                )
