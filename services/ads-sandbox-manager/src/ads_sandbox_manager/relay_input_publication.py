"""Internal relay publication under the existing claim; no runtime activation."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.pair_compute import RelayRuntime
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.relay_input_kube import RelayInputAdapter
from ads_sandbox_manager.relay_inputs import INPUT_ROLES, input_payload
from ads_sandbox_manager.store import SandboxSession


class RelayInputPublication:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: PairIntentRepository,
        kube: RelayInputAdapter,
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
            raise RuntimeError("relay publication configuration changed")

    def _finished(self, task: asyncio.Task[str]) -> None:
        self._dispatches.discard(task)
        if not task.cancelled():
            task.exception()

    async def _dispatch(self, intent: PairIntent, role: str) -> str:
        self._configuration(intent)
        async with asyncio.timeout(2 * self.settings.control_seconds):
            uid = await self.kube.create(
                intent.binding(), role, intent.relay_inputs[role]["payload"]
            )
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            self._configuration(intent)
            await self.repository.settle_relay_input(db, intent, role)
        return uid

    async def drain(self) -> None:
        """Stop producers before this bounded join; this is not retirement evidence."""
        if self._dispatches:
            async with asyncio.timeout(self.settings.control_seconds):
                await asyncio.wait(tuple(self._dispatches))

    async def prepare(
        self,
        row: SandboxSession,
        generation: UUID,
        runtime: RelayRuntime,
    ) -> PairIntent:
        config = self.settings.session_objects
        if config is None or row.claimed_by is None:
            raise PairClaimLost("a configured provisioning claim is required")
        owner = row.claimed_by
        async with asyncio.timeout(config.create_seconds):
            for role in INPUT_ROLES:
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    intent = await self.repository.owned(db, row, owner, generation)
                    self._configuration(intent)
                payload = intent.relay_inputs[role]["payload"]
                if payload is None:
                    pods = {r: intent.compute_uids[f"Pod/{r}"] for r in INPUT_ROLES}
                    service = intent.control_uids["Service/egress-relay"]
                    if any(uid is None for uid in pods.values()) or service is None:
                        raise RuntimeError("recorded relay dependencies required")
                    recorded = {r: str(uid) for r, uid in pods.items()}
                    address = await self.kube.dependencies(intent.binding(), recorded, service)
                    payload = input_payload(
                        intent.binding(),
                        role,
                        runtime,
                        intent.relay_custody["public_keys"],
                        intent.relay_custody["uid"],
                        recorded,
                        service,
                        address,
                    )
                elif payload["runtime"] != asdict(runtime):
                    raise RuntimeError("committed relay runtime changed")
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(intent)
                    intent, dispatch = await self.repository.reserve_relay_input(
                        db, row, owner, generation, role, payload
                    )
                if dispatch:
                    operation = asyncio.create_task(
                        self._dispatch(intent, role), name="relay-input-dispatch"
                    )
                    self._dispatches.add(operation)
                    operation.add_done_callback(self._finished)
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
                            intent.binding(), role, payload, intent.relay_inputs[role]["uid"]
                        )
                        if uid is None:
                            await asyncio.sleep(0.05)
                assert uid is not None
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(intent)
                    intent = await self.repository.bind_relay_input(
                        db, row, owner, generation, role, uid
                    )
            return intent
