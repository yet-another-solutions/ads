from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID, uuid4

import msgspec

from ads_sandbox_manager.config import Settings

TOPIC = "ads.sandbox.manager.barrier"
GROUP = "ads-sandbox-manager"
log = logging.getLogger(__name__)


class BarrierRequest(msgspec.Struct, frozen=True, tag="barrier-request", tag_field="type"):
    barrier_id: UUID
    sandbox_id: UUID
    initiator: UUID
    members: tuple[UUID, ...]


class BarrierAck(msgspec.Struct, frozen=True, tag="barrier-ack", tag_field="type"):
    barrier_id: UUID
    sandbox_id: UUID
    initiator: UUID
    member: UUID


BarrierMessage = BarrierRequest | BarrierAck


class CoordinationPort(Protocol):
    replica_id: UUID

    async def members(self) -> set[UUID]: ...
    async def subscribed(self, sandbox_id: UUID) -> None: ...
    async def broadcast(self, message: BarrierMessage) -> None: ...


@dataclass
class Round:
    request: BarrierRequest
    received: set[UUID] = field(default_factory=set)
    changed: asyncio.Event = field(default_factory=asyncio.Event)


class ManagerBarrier:
    """Bounded snapshot agreement, NOT consensus, fencing, or a delivery guarantee."""

    def __init__(self, settings: Settings, port: CoordinationPort) -> None:
        self.settings = settings
        self.port = port
        self.rounds: dict[UUID, Round] = {}
        self.participants: dict[UUID, asyncio.Task[None]] = {}

    async def wait(self, sandbox_id: UUID) -> None:
        barrier_id = uuid4()
        members: set[UUID] = set()
        round_: Round | None = None
        try:
            async with asyncio.timeout(self.settings.barrier_seconds):
                members = await self.port.members()
                if self.port.replica_id not in members:
                    raise RuntimeError("local replica absent from membership snapshot")
                request = BarrierRequest(
                    barrier_id, sandbox_id, self.port.replica_id, tuple(sorted(members))
                )
                round_ = Round(request, {self.port.replica_id})
                self.rounds[barrier_id] = round_
                await self.port.broadcast(request)
                while not members <= round_.received:
                    round_.changed.clear()
                    await round_.changed.wait()
        except Exception:
            missing = members - (round_.received if round_ else set())
            log.warning(
                "manager barrier incomplete; proceeding sandbox=%s barrier=%s missing=%s",
                sandbox_id,
                barrier_id,
                sorted(map(str, missing)),
            )
        finally:
            self.rounds.pop(barrier_id, None)

    async def accept(self, message: BarrierMessage) -> None:
        if isinstance(message, BarrierAck):
            round_ = self.rounds.get(message.barrier_id)
            if (
                round_ is not None
                and message.sandbox_id == round_.request.sandbox_id
                and message.initiator == round_.request.initiator
                and message.member in round_.request.members
            ):
                round_.received.add(message.member)
                round_.changed.set()
            return
        if (
            self.port.replica_id not in message.members
            or message.initiator == self.port.replica_id
            or message.initiator not in message.members
            or message.barrier_id in self.participants
        ):
            return
        # Never block the coordination reader while waiting for another consumer's rebalance.
        task = asyncio.create_task(self._ack(message), name="manager-barrier-ack")
        self.participants[message.barrier_id] = task
        task.add_done_callback(lambda _: self.participants.pop(message.barrier_id, None))

    async def _ack(self, request: BarrierRequest) -> None:
        try:
            async with asyncio.timeout(self.settings.barrier_seconds):
                await self.port.subscribed(request.sandbox_id)
                await self.port.broadcast(
                    BarrierAck(
                        request.barrier_id,
                        request.sandbox_id,
                        request.initiator,
                        self.port.replica_id,
                    )
                )
        except Exception:
            log.warning(
                "manager barrier acknowledgement unavailable sandbox=%s", request.sandbox_id
            )

    async def stop(self) -> None:
        tasks = list(self.participants.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.participants.clear()
