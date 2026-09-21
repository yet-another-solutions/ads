"""Independent configuration delivery. Execution admission uses installation only at startup."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

import msgspec
import structlog

from ads_commons.egress import (
    EgressApplied,
    EgressApply,
    EgressPing,
    ProjectEgressSnapshot,
    Revision,
    canonical_settings,
)

log = structlog.get_logger("ads_sandbox_ipc.egress")


class StaleRevision(Exception):
    """Only raised for a structurally valid exact stale_revision response."""


class EgressTransport(Protocol):
    async def apply(self, body: EgressApply) -> EgressApplied: ...
    async def ping(self) -> EgressPing: ...
    async def relays_healthy(self) -> bool: ...


class RevisionRecord(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    project_id: UUID
    revision: Revision


class RevisionFloor:
    """Revision knowledge only. A separate subdirectory survives PID-store cleanup."""

    def __init__(self, directory: Path, project_id: UUID) -> None:
        self.directory = directory / "egress"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "revision.json"
        self.project_id = project_id
        self.revision = 0
        if self.path.exists():
            record = msgspec.json.decode(self.path.read_bytes(), type=RevisionRecord)
            if record.project_id != project_id:
                raise ValueError("persisted egress project binding mismatch")
            self.revision = record.revision

    def advance(self, revision: int) -> None:
        if revision <= self.revision:
            return
        record = msgspec.json.decode(
            msgspec.json.encode(RevisionRecord(self.project_id, revision)), type=RevisionRecord
        )
        temporary = self.directory / f"{uuid4()}.tmp"
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(msgspec.json.encode(record))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self.revision = record.revision
        finally:
            temporary.unlink(missing_ok=True)


class EgressDelivery:
    """Two-attempt delivery budget, durable floor, and process-instance fencing."""

    def __init__(
        self,
        project_id: UUID,
        floor: RevisionFloor,
        transport: EgressTransport,
        timeout_seconds: float = 10,
    ) -> None:
        self.project_id = project_id
        self.floor = floor
        self.transport = transport
        self.timeout_seconds = timeout_seconds
        self.instance: UUID | None = None
        self.installed: EgressApplied | None = None
        self.snapshot: ProjectEgressSnapshot | None = None
        self.failed = False
        self.stopped = False
        self.ever_installed = asyncio.Event()
        self._lock = asyncio.Lock()
        self._reapply: asyncio.Task[None] | None = None
        self._health_sequence = 0
        self._observed_sequence = 0

    async def receive(self, project_id: UUID, snapshot: ProjectEgressSnapshot) -> None:
        if self.stopped or self.failed or project_id != self.project_id:
            return
        async with self._lock:
            if self.stopped or self.failed or snapshot.revision < self.floor.revision:
                return
            snapshot = ProjectEgressSnapshot(
                snapshot.revision, canonical_settings(snapshot.settings)
            )
            try:
                self.floor.advance(snapshot.revision)
            except Exception:
                self.failed = True
                log.warning("egress_revision_persistence_failed")
                return
            self.snapshot = snapshot
            await self._apply(snapshot)

    async def _apply(self, snapshot: ProjectEgressSnapshot) -> None:
        for attempt in range(2):
            if self.stopped or self.failed:
                return
            try:
                async with asyncio.timeout(self.timeout_seconds):
                    if self.instance is None:
                        ping = await self.transport.ping()
                        if not ping.healthy:
                            raise RuntimeError("egress unavailable")
                        self.instance = ping.instance_id
                    expected = self.instance
                    result = await self.transport.apply(EgressApply(self.project_id, snapshot))
                    if self.stopped or result.instance_id != expected or self.instance != expected:
                        log.warning("egress_apply_unexpected_instance")
                        return  # consumed no-op, not an ordinary failed attempt
                    if result.revision != snapshot.revision:
                        raise RuntimeError("egress apply revision mismatch")
                    self.installed = result
                    self.ever_installed.set()
                    return
            except StaleRevision:
                return  # not installation evidence and never clears a previous latch
            except asyncio.CancelledError:
                raise
            except Exception:
                log.warning("egress_apply_failed", attempt=attempt + 1)
        self.failed = True

    async def healthy(self) -> bool:
        if self.stopped or self.failed:
            return False
        self._health_sequence += 1
        sequence = self._health_sequence
        try:
            async with asyncio.timeout(self.timeout_seconds):
                ping, relays = await asyncio.gather(
                    self.transport.ping(), self.transport.relays_healthy()
                )
            if not ping.healthy or not relays:
                return False
            if sequence < self._observed_sequence:
                return not self.failed and not self.stopped
            self._observed_sequence = sequence
            changed = self.instance != ping.instance_id
            if changed:
                self.instance = ping.instance_id
                self.installed = None
            if (
                changed
                and self.snapshot is not None
                and (self._reapply is None or self._reapply.done())
            ):
                self._reapply = asyncio.create_task(self._background_apply())
            return not self.failed and not self.stopped
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def _background_apply(self) -> None:
        async with self._lock:
            while (
                not self.stopped
                and not self.failed
                and self.snapshot is not None
                and self.installed is None
            ):
                observed = self.instance
                await self._apply(self.snapshot)
                # A further UUID observation while this task was active must not
                # be lost. Only that new observation schedules another delivery,
                # not stale_revision or an unexpected-UUID success by itself.
                if self.instance == observed:
                    break

    async def close(self) -> None:
        self.stopped = True
        if self._reapply is not None:
            self._reapply.cancel()
            await asyncio.gather(self._reapply, return_exceptions=True)
