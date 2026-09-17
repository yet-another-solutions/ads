from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from time import monotonic

from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.golden import GoldenEnsure
from ads_sandbox_manager.health import Dependencies
from ads_sandbox_manager.kafka import KafkaRuntime

log = logging.getLogger(__name__)


class ManagerRuntime:
    def __init__(
        self,
        settings: Settings,
        golden: GoldenEnsure,
        dependencies: Dependencies,
        kafka: KafkaRuntime,
    ) -> None:
        self.settings = settings
        self.golden = golden
        self.dependencies = dependencies
        self.kafka = kafka
        self._ready = False
        self._checked = 0.0
        self._task: asyncio.Task[None] | None = None

    @property
    def ready(self) -> bool:
        return (
            self._task is not None
            and not self._task.done()
            and self._ready
            and self.kafka.ready
            and monotonic() - self._checked
            < self.settings.poll_seconds + self.settings.control_seconds * 3
        )

    async def check(self) -> None:
        self._ready = False
        try:
            # A whole pass is bounded as well as every individual Kubernetes call.
            async with asyncio.timeout(self.settings.control_seconds * 3):
                golden_ready = await self.golden.poll()
                self._ready = golden_ready and await self.dependencies.check()
        except ApiException as exc:
            # 409 is the Job/PVC name lock or stale delete precondition; reread next pass.
            # 404 also covers a resource disappearing between two live observations.
            if exc.status not in (404, 409):
                log.warning("golden observation unavailable (Kubernetes status %s)", exc.status)
        except Exception as exc:
            # Never serialize SQL URLs, SASL credentials, API response bodies, or tokens.
            log.warning("golden observation unavailable (%s)", type(exc).__name__)
        finally:
            self._checked = monotonic()

    async def _run(self) -> None:
        while True:
            await self.check()
            await asyncio.sleep(self.settings.poll_seconds)

    async def start(self) -> None:
        if self._task is None:
            await self.kafka.start()
            self._task = asyncio.create_task(self._run(), name="manager-golden-ensure")

    async def stop(self) -> None:
        self._ready = False
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        await self.kafka.stop()
