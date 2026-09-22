"""Commit pair control intent before external work; never assert runtime readiness."""

from __future__ import annotations

import asyncio
from typing import Protocol, cast
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.pair_kube import ControlKind
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.pair_store import (
    CONTROL_RESOURCES,
    PairClaimLost,
    PairIntent,
    PairIntentRepository,
    resource_key,
)
from ads_sandbox_manager.store import SandboxSession


class PairControlKubernetes(Protocol):
    @property
    def namespace(self) -> str: ...
    @property
    def golden_version(self) -> str: ...
    async def ensure(
        self, pair: PairBinding, kind: ControlKind, role: str, uid: str | None = None
    ) -> str: ...


class PairControlProvisioner:
    """Internal step under an existing authenticated manager provisioning claim.

    Failure/cancellation propagates to the lifecycle caller. Durable intent and
    committed UIDs survive; unknown UID never becomes assumed absence. A stale
    external call may finish late, but cannot advance the claim or later steps.
    Cleanup must inspect the retained generation, not recreate or forget it.
    """

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: PairIntentRepository,
        kube: PairControlKubernetes,
    ) -> None:
        self.settings, self.sessions = settings, sessions
        self.repository, self.kube = repository, kube

    def _configuration(self, intent: PairIntent | None = None) -> None:
        wanted = (self.settings.namespace, self.settings.golden_version)
        if (self.kube.namespace, self.kube.golden_version) != wanted or (
            intent is not None and (intent.namespace, intent.golden_version) != wanted
        ):
            raise RuntimeError("pair control builder configuration changed")

    async def _current(self, row: SandboxSession, owner: UUID, generation: UUID) -> PairIntent:
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            intent = await self.repository.owned(db, row, owner, generation)
            self._configuration(intent)
        return intent

    async def prepare(self, row: SandboxSession) -> PairIntent:
        config = self.settings.session_objects
        if config is None or row.claimed_by is None:
            raise PairClaimLost("a configured provisioning claim is required")
        owner = row.claimed_by
        self._configuration()
        async with asyncio.timeout(config.create_seconds):
            async with (
                asyncio.timeout(self.settings.control_seconds),
                self.sessions.begin() as db,
            ):
                intent = await self.repository.begin(
                    db,
                    row,
                    owner,
                    namespace=self.settings.namespace,
                    golden_version=self.settings.golden_version,
                )
            generation = intent.generation
            for kind, role in CONTROL_RESOURCES:
                # Commit/close the transaction before entering the API adapter.
                intent = await self._current(row, owner, generation)
                uid = await self.kube.ensure(
                    intent.binding(),
                    cast(ControlKind, kind),
                    role,
                    intent.control_uids[resource_key(kind, role)],
                )
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(intent)
                    await self.repository.bind(db, row, owner, generation, kind, role, uid)
            # A fully captured control set is still not compute or execution-ready.
            return await self._current(row, owner, generation)
