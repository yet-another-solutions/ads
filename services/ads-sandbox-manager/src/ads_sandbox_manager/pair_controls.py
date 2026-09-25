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
    async def observe(
        self, pair: PairBinding, kind: ControlKind, role: str, uid: str | None = None
    ) -> str | None: ...


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
        self._dispatches: set[asyncio.Task[str]] = set()

    def _finished(self, task: asyncio.Task[str]) -> None:
        self._dispatches.discard(task)
        if not task.cancelled():
            # The caller may already have timed out. Retrieve exceptions without
            # logging API/SQL bodies; durable inflight evidence remains authoritative.
            task.exception()

    async def _dispatch(self, intent: PairIntent, kind: ControlKind, role: str) -> str:
        self._configuration(intent)
        # ensure performs at most read/create/read. Bound the retained coroutine
        # too; cancelling it cannot prove that an underlying SDK thread stopped.
        async with asyncio.timeout(3 * self.settings.control_seconds):
            uid = await self.kube.ensure(intent.binding(), kind, role)
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            self._configuration(intent)
            await self.repository.settle(db, intent, kind, role)
        return uid

    async def drain(self) -> None:
        """Bounded lifecycle join, not a quiescence or settlement verdict.

        Timeout/cancellation of the join does not cancel original operations.
        The eventual runtime owner must drain before closing SQL/Kubernetes.
        Process loss still leaves unresolved durable evidence.
        """
        if self._dispatches:
            async with asyncio.timeout(self.settings.control_seconds):
                await asyncio.wait(tuple(self._dispatches))

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

    async def prepare(self, row: SandboxSession, *, resume: bool = False) -> PairIntent:
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
                    resume=resume,
                )
            generation = intent.generation
            uid: str | None
            for kind, role in CONTROL_RESOURCES:
                while True:
                    # Commit dispatch evidence before any create-capable call.
                    async with (
                        asyncio.timeout(self.settings.control_seconds),
                        self.sessions.begin() as db,
                    ):
                        intent, dispatch = await self.repository.dispatch(
                            db, row, owner, generation, kind, role
                        )
                        self._configuration(intent)
                    known = intent.control_uids[resource_key(kind, role)]
                    if dispatch:
                        operation = asyncio.create_task(
                            self._dispatch(intent, cast(ControlKind, kind), role),
                            name="pair-control-dispatch",
                        )
                        self._dispatches.add(operation)
                        operation.add_done_callback(self._finished)
                        # Only the original reservation runs here. Caller death
                        # cannot discard its normal-return settlement evidence.
                        # wait does not forward caller cancellation to the task.
                        # Unlike a cancelled shield in Python 3.14, it does not
                        # log a later exception outside our completion handler.
                        await asyncio.wait((operation,))
                        uid = operation.result()
                    elif known is not None:
                        # A known UID makes ensure observation-only, preserving
                        # the adapter's strict spec/replacement checks.
                        uid = await self.kube.ensure(
                            intent.binding(), cast(ControlKind, kind), role, known
                        )
                    else:
                        uid = await self.kube.observe(
                            intent.binding(), cast(ControlKind, kind), role
                        )
                        if uid is not None:
                            # Observation proves identity, not compatible spec.
                            # Supplying its UID forbids ensure from recreating it.
                            uid = await self.kube.ensure(
                                intent.binding(), cast(ControlKind, kind), role, uid
                            )
                    if uid is not None:
                        break
                    # Another worker may still complete the sole dispatch.
                    # Poll reads within the existing create deadline, never retry a write.
                    await asyncio.sleep(0.05)
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(intent)
                    await self.repository.bind(db, row, owner, generation, kind, role, uid)
            # A fully captured control set is still not compute or execution-ready.
            return await self._current(row, owner, generation)
