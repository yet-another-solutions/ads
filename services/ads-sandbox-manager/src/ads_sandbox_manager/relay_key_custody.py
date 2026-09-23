"""Internal custody step under an existing pair claim, not runtime activation."""

from __future__ import annotations

import asyncio
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.relay_key_kube import RelayKeyAdapter
from ads_sandbox_manager.relay_keys import RelayKeys
from ads_sandbox_manager.store import SandboxSession


class RelayKeyCustody:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: PairIntentRepository,
        kube: RelayKeyAdapter,
    ) -> None:
        self.settings, self.sessions = settings, sessions
        self.repository, self.kube = repository, kube
        self._dispatches: set[asyncio.Task[str]] = set()

    def _configuration(self, intent: PairIntent) -> None:
        wanted = (self.settings.namespace, self.settings.golden_version)
        if (intent.namespace, intent.golden_version) != wanted or (
            self.kube.namespace,
            self.kube.golden_version,
        ) != wanted:
            raise RuntimeError("relay custody configuration changed")

    def _finished(self, task: asyncio.Task[str]) -> None:
        self._dispatches.discard(task)
        if not task.cancelled():
            task.exception()  # Retrieve, never log a detached failure.

    async def _dispatch(self, intent: PairIntent, keys: RelayKeys) -> str:
        self._configuration(intent)
        async with asyncio.timeout(2 * self.settings.control_seconds):
            uid = await self.kube.create(
                intent.binding(), intent.relay_custody["public_keys"], keys
            )
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            self._configuration(intent)
            await self.repository.settle_relay_keys(db, intent)
        return uid

    async def drain(self) -> None:
        """Bounded join only. Stop producers before calling and closing dependencies."""
        if self._dispatches:
            async with asyncio.timeout(self.settings.control_seconds):
                await asyncio.wait(tuple(self._dispatches))

    async def prepare(self, row: SandboxSession, generation: UUID) -> PairIntent:
        config = self.settings.session_objects
        if config is None or row.claimed_by is None:
            raise PairClaimLost("a configured provisioning claim is required")
        owner = row.claimed_by
        async with asyncio.timeout(config.create_seconds):
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                intent = await self.repository.owned(db, row, owner, generation)
                self._configuration(intent)
                # Generate only while the existing session/intent lock confirms
                # no prior reservation. Both public keys commit with the dispatch.
                # No network/file I/O occurs here; rollback permits a fresh try.
                keys = (
                    RelayKeys.generate() if intent.relay_custody["dispatch"] == "unissued" else None
                )
                dispatch = False
                if keys is not None:
                    intent, dispatch = await self.repository.reserve_relay_keys(
                        db, row, owner, generation, keys.public_keys()
                    )
            if dispatch:
                assert keys is not None
                operation = asyncio.create_task(
                    self._dispatch(intent, keys), name="relay-custody-dispatch"
                )
                self._dispatches.add(operation)
                operation.add_done_callback(self._finished)
                keys = None
                # Cancellation of the caller never cancels the reserved operation
                # or discards normal-return settlement after a delayed SDK write.
                await asyncio.wait((operation,))
                uid = operation.result()
            else:
                uid = None
                while uid is None:
                    async with (
                        asyncio.timeout(self.settings.control_seconds),
                        self.sessions.begin() as db,
                    ):
                        intent = await self.repository.owned(db, row, owner, generation)
                        self._configuration(intent)
                    uid = await self.kube.observe(
                        intent.binding(),
                        intent.relay_custody["public_keys"],
                        intent.relay_custody["uid"],
                    )
                    if uid is None:
                        await asyncio.sleep(0.05)
            assert uid is not None
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                self._configuration(intent)
                return await self.repository.bind_relay_keys(db, row, owner, generation, uid)
