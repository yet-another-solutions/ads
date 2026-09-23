"""Reserved persistent resources only, not egress activation or ready state."""

from __future__ import annotations

import asyncio
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.egress_state_kube import EgressStateAdapter
from ads_sandbox_manager.egress_state_store import EgressState, EgressStateRepository, WrappingKey
from ads_sandbox_manager.pair_store import PairClaimLost
from ads_sandbox_manager.store import SandboxSession


class EgressStatePublication:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: EgressStateRepository,
        kube: EgressStateAdapter,
    ) -> None:
        self.settings, self.sessions = settings, sessions
        self.repository, self.kube = repository, kube
        self._dispatches: set[asyncio.Task[str]] = set()

    def _configuration(self, state: EgressState) -> None:
        if state.namespace != self.settings.namespace or (
            self.kube.kube.settings.namespace != self.settings.namespace
        ):
            raise RuntimeError("persistent state publication namespace changed")

    def _finished(self, task: asyncio.Task[str]) -> None:
        self._dispatches.discard(task)
        if not task.cancelled():
            task.exception()

    async def drain(self) -> None:
        """Bounded join after stopping producers; never proof of remote release."""
        if self._dispatches:
            async with asyncio.timeout(self.settings.control_seconds):
                await asyncio.wait(tuple(self._dispatches))

    async def _dispatch(self, state: EgressState, role: str, key: WrappingKey | None) -> str:
        self._configuration(state)
        async with asyncio.timeout(2 * self.settings.control_seconds):
            if role == "key":
                assert key is not None
                uid = await self.kube.create_key(state, key)
            else:
                uid = await self.kube.create_volume(state)
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            self._configuration(state)
            await self.repository.settle(db, state, role)
        return uid

    async def _join_or_observe(
        self, state: EgressState, role: str, dispatch: bool, key: WrappingKey | None
    ) -> str | None:
        self._configuration(state)
        if dispatch:
            operation = asyncio.create_task(
                self._dispatch(state, role, key), name=f"egress-state-{role}-dispatch"
            )
            self._dispatches.add(operation)
            operation.add_done_callback(self._finished)
            # Caller cancellation never cancels the retained original writer.
            await asyncio.wait((operation,))
            return operation.result()
        if role == "key":
            return await self.kube.observe_key(state)
        return await self.kube.observe_volume(state)

    async def prepare(
        self, row: SandboxSession, generation: UUID, *, storage_bytes: int
    ) -> EgressState:
        config = self.settings.session_objects
        if config is None or row.claimed_by is None:
            raise PairClaimLost("a configured provisioning claim is required")
        owner = row.claimed_by
        async with asyncio.timeout(config.create_seconds):
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                state, key = await self.repository.reserve(
                    db, row, owner, generation, storage_bytes=storage_bytes
                )
                self._configuration(state)
            for role in ("key", "volume"):
                if role == "key":
                    dispatch = key is not None
                else:
                    async with (
                        asyncio.timeout(self.settings.control_seconds),
                        self.sessions.begin() as db,
                    ):
                        state, dispatch = await self.repository.reserve_volume(
                            db, row, owner, generation, state.state_id
                        )
                        self._configuration(state)
                uid = await self._join_or_observe(state, role, dispatch, key)
                key = None
                while uid is None:
                    await asyncio.sleep(0.05)
                    async with (
                        asyncio.timeout(self.settings.control_seconds),
                        self.sessions.begin() as db,
                    ):
                        state = await self.repository.owned(
                            db, row, owner, generation, state.state_id
                        )
                        self._configuration(state)
                    uid = await self._join_or_observe(state, role, False, None)
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(state)
                    state = await self.repository.bind(
                        db, row, owner, generation, state.state_id, role, uid
                    )
            return state
