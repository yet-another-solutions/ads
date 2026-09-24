"""Dependency-ordered paired creation, using the existing provisioning claim."""

from __future__ import annotations

import asyncio
from typing import Protocol
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.ca import CaEnsure
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.egress_compute_publication import EgressComputePublication
from ads_sandbox_manager.egress_state_kube import EgressStateAdapter
from ads_sandbox_manager.egress_state_publication import EgressStatePublication
from ads_sandbox_manager.egress_state_store import EgressStateRepository
from ads_sandbox_manager.golden import GoldenEnsure
from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_compute_kube import PairComputeAdapter
from ads_sandbox_manager.pair_compute_publication import PairComputePublication
from ads_sandbox_manager.pair_controls import PairControlProvisioner
from ads_sandbox_manager.pair_ipc_kube import PairIpcAdapter
from ads_sandbox_manager.pair_ipc_publication import PairIpcPublication
from ads_sandbox_manager.pair_ipc_store import PairIpcRepository
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_runtime import pair_runtime
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.pair_volume_kube import PairVolumeAdapter
from ads_sandbox_manager.pair_volume_publication import PairVolumePublication
from ads_sandbox_manager.pair_volume_store import PairVolumeRepository
from ads_sandbox_manager.relay_input_kube import RelayInputAdapter
from ads_sandbox_manager.relay_input_publication import RelayInputPublication
from ads_sandbox_manager.relay_key_custody import RelayKeyCustody
from ads_sandbox_manager.relay_key_kube import RelayKeyAdapter
from ads_sandbox_manager.store import SandboxSession


class PairTopics(Protocol):
    async def prepare(self, sandbox_id: UUID) -> None: ...


class PairCreation:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        kube: KubeClient,
        golden: GoldenEnsure,
        ca: CaEnsure,
        topics: PairTopics,
    ) -> None:
        self.settings, self.sessions, self.topics = settings, sessions, topics
        self.runtime = pair_runtime(settings)  # Fail before any resource API call.
        self.repository = repository = PairIntentRepository()
        controls = PairControlAdapter(kube)
        compute = PairComputeAdapter(kube, controls)
        self.controls = PairControlProvisioner(settings, sessions, repository, controls)
        self.volumes = PairVolumePublication(
            settings,
            sessions,
            PairVolumeRepository(repository),
            PairVolumeAdapter(kube, golden, ca),
        )
        self.compute = PairComputePublication(settings, sessions, repository, compute)
        self.keys = RelayKeyCustody(settings, sessions, repository, RelayKeyAdapter(kube))
        self.inputs = RelayInputPublication(settings, sessions, repository, RelayInputAdapter(kube))
        self.state = EgressStatePublication(
            settings, sessions, EgressStateRepository(repository), EgressStateAdapter(kube)
        )
        self.egress = EgressComputePublication(settings, sessions, repository, compute)
        self.ipc = PairIpcPublication(
            settings, sessions, PairIpcRepository(repository), PairIpcAdapter(compute)
        )
        self._dispatches: set[asyncio.Task[None]] = set()

    def _finished(self, task: asyncio.Task[None]) -> None:
        self._dispatches.discard(task)
        if not task.cancelled():
            task.exception()

    async def drain(self) -> None:
        for publisher in (
            self.controls,
            self.volumes,
            self.compute,
            self.keys,
            self.inputs,
            self.state,
            self.egress,
            self.ipc,
        ):
            await publisher.drain()
        if self._dispatches:
            async with asyncio.timeout(self.settings.control_seconds):
                await asyncio.wait(tuple(self._dispatches))

    async def _current(self, row: SandboxSession, generation: UUID) -> SandboxSession:
        assert row.claimed_by is not None
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            await self.repository.owned(db, row, row.claimed_by, generation)
            current = await db.get(SandboxSession, row.session_id)
            assert current is not None
            return current

    async def _completed(self, row: SandboxSession, generation: UUID) -> SandboxSession:
        """IPC may win the ready transaction immediately after its UID bind."""
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            current = await db.get(
                SandboxSession, row.session_id, with_for_update=True, populate_existing=True
            )
            if current is None:
                raise PairClaimLost("completed paired session disappeared")
            if current.status == "creating":
                assert row.claimed_by is not None
                await self.repository.owned(db, row, row.claimed_by, generation)
                return current
            intent = await self.repository.snapshot(db, generation)
            if (
                intent is None
                or intent.creation_fenced
                or current.status != "ready"
                or current.status_changed_at <= row.status_changed_at
                or (current.sandbox_id, current.project_id, current.claimed_by)
                != (row.sandbox_id, row.project_id, row.claimed_by)
                or (
                    intent.session_id,
                    intent.sandbox_id,
                    intent.project_id,
                    intent.claim_owner,
                    intent.claim_changed,
                )
                != (
                    row.session_id,
                    row.sandbox_id,
                    row.project_id,
                    row.claimed_by,
                    row.status_changed_at,
                )
                or current.guest_deployment_uid is not None
                or current.ipc_deployment_uid is not None
                or current.pvc_uid != intent.volume_resources["workspace"]["uid"]
                or current.ipc_pvc_uid != intent.ipc_resources["volume"]["uid"]
                or current.ipc_pod_uid != intent.ipc_resources["pod"]["uid"]
            ):
                raise PairClaimLost("completed paired claim changed")
            self._settled(intent.volume_resources)
            self._settled(intent.ipc_resources)
            return current  # Read-only acceptance of the separately committed ready transition.

    async def _topic_write(self, intent: PairIntent) -> None:
        config = self.settings.session_objects
        assert config is not None
        async with asyncio.timeout(config.create_seconds):
            await self.topics.prepare(intent.sandbox_id)
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            current = await self.repository._settlement_intent(db, intent)
            if current.topics_dispatch not in ("inflight", "settled"):
                raise PairClaimLost("paired topics were never dispatched")
            current.topics_dispatch = "settled"

    async def _topics(self, row: SandboxSession, generation: UUID) -> None:
        assert row.claimed_by is not None
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            intent = await self.repository.owned(db, row, row.claimed_by, generation)
            dispatch = intent.topics_dispatch == "unissued"
            if dispatch:
                intent.topics_dispatch = "inflight"
            elif intent.topics_dispatch != "settled":
                raise PairClaimLost("paired topic write remains ambiguous")
        if dispatch:
            task = asyncio.create_task(self._topic_write(intent), name="pair-topic-dispatch")
            self._dispatches.add(task)
            task.add_done_callback(self._finished)
            await asyncio.wait((task,))
            task.result()
        await self._current(row, generation)

    @staticmethod
    def _settled(entries: Object) -> None:
        if any(value["dispatch"] != "settled" or not value["uid"] for value in entries.values()):
            raise PairClaimLost("paired publication is not settled and UID bound")

    async def build(self, row: SandboxSession, *, resume: bool) -> SandboxSession:
        config = self.settings.session_objects
        assert config is not None
        if resume:
            raise PairClaimLost("paired resume requires explicit retained-state transfer")
        async with asyncio.timeout(config.create_seconds):
            intent = await self.controls.prepare(row)
            if not all(intent.control_uids.values()) or set(intent.control_dispatch.values()) != {
                "settled"
            }:
                raise PairClaimLost("paired controls are not settled")
            generation = intent.generation
            volumes = await self.volumes.prepare(row, generation)
            self._settled(volumes.volume_resources)
            row = await self._current(row, generation)
            # Existing best-effort replica barrier precedes guest and IPC compute.
            await self._topics(row, generation)
            compute = await self.compute.prepare(
                row, generation, self.runtime.guest, self.runtime.relay
            )
            if any(
                compute.compute_dispatch[f"Pod/{role}"] != "settled"
                for role in ("guest", "guest-relay", "egress-relay")
            ):
                raise PairClaimLost("paired compute writes remain ambiguous")
            keys = await self.keys.prepare(row, generation)
            self._settled({"custody": keys.relay_custody})
            inputs = await self.inputs.prepare(row, generation, self.runtime.relay)
            self._settled(inputs.relay_inputs)
            state = await self.state.prepare(
                row, generation, storage_bytes=self.runtime.state_bytes
            )
            if state.key_dispatch != "settled" or state.volume_dispatch != "settled":
                raise PairClaimLost("paired persistent state writes remain ambiguous")
            await self.egress.prepare(row, generation, self.runtime.egress)
            assert self.settings.ads_service_subject is not None
            ipc = await self.ipc.prepare(row, generation, self.settings.ads_service_subject)
            self._settled(ipc.ipc_resources)
            return await self._completed(row, generation)
