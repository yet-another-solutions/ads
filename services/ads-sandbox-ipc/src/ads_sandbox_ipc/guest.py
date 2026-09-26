from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from ads_commons.sandbox import SandboxRequest, SandboxResult
from ads_sandbox_ipc.config import Settings
from ads_sandbox_ipc.pid_store import GuestPid, PidStore


@dataclass(frozen=True, slots=True)
class Pod:
    name: str
    uid: str


@dataclass(frozen=True, slots=True)
class Frame:
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int | None = None


class Process(Protocol):
    async def read(self) -> Frame: ...
    async def close(self) -> None: ...


class Kubernetes(Protocol):
    async def ready_pod(self) -> Pod | None: ...
    async def start(self, pod: Pod, argv: list[str], stdin: bytes) -> Process: ...
    async def read_pid(self, pod: Pod) -> int | None: ...
    async def kill_tree(self, pod: Pod, pid: int) -> None: ...
    async def clear_pid(self, pod: Pod) -> None: ...


class GuestTrust(Protocol):
    async def install(self, pod: Pod) -> None: ...


class CappedOutput:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def append(self, value: bytes) -> None:
        available = self.limit - len(self.data)
        self.data.extend(value[:available])
        self.truncated |= len(value) > available

    def text(self) -> str:
        # Drop incomplete/invalid UTF-8 instead of expanding replacement bytes beyond the cap.
        return self.data.decode("utf-8", errors="ignore")


class GuestExecutor:
    """Exec/PID lifecycle, isolated from Kafka and authentication."""

    def __init__(
        self, settings: Settings, kube: Kubernetes, store: PidStore, trust: GuestTrust | None = None
    ) -> None:
        self.settings = settings
        self.kube = kube
        self.store = store
        self.pod: Pod | None = None
        self.clean = True
        self.trust = trust

    async def prepare(self) -> bool:
        pod = await self.kube.ready_pod()
        if pod is None:
            return False
        # A replacement pod has a new PID namespace. Never apply old numbers to it.
        entries = self.store.entries()
        pids = {entry.pid for _, entry in entries if entry.pod_uid == pod.uid}
        guest_pid = await self.kube.read_pid(pod)
        if guest_pid is not None:
            pids.add(guest_pid)
        for pid in sorted(pids):
            await self.kube.kill_tree(pod, pid)
        await self.kube.clear_pid(pod)
        self.store.clear()
        if self.trust is not None:
            await self.trust.install(pod)
        self.pod = pod
        ping = SandboxRequest(uuid4(), uuid4(), uuid4(), "shell", "true")
        result = await self.execute(ping, asyncio.Event())
        return result.exit_code == 0 and not result.is_error

    async def execute(self, request: SandboxRequest, abort: asyncio.Event) -> SandboxResult:
        started = time.monotonic()
        stdout = CappedOutput(self.settings.stdout_bytes)
        stderr = CappedOutput(self.settings.stderr_bytes)
        pod = self.pod
        if pod is None or not self.clean:
            return SandboxResult(
                request.execution_id, -1, "", "", False, 0, True, "guest unavailable"
            )
        argv = ["ads-session-exec", request.kind]
        stdin = b""
        if request.kind == "shell":
            argv.append(request.payload)
        else:
            stdin = request.payload.encode()
        process: Process | None = None
        pid: int | None = None
        code = -1
        error = ""
        exited = False
        read_task: asyncio.Task[Frame] | None = None
        self.clean = False
        try:
            async with asyncio.timeout(self.settings.timeout_seconds):
                if abort.is_set():
                    error = "execution aborted"
                else:
                    process = await self.kube.start(pod, argv, stdin)
                    read_task = asyncio.create_task(process.read())
                    while True:
                        if pid is None:
                            pid = await self.kube.read_pid(pod)
                            if pid is not None:
                                self.store.save(request.execution_id, GuestPid(pod.uid, pid))
                        if abort.is_set():
                            error = "execution aborted"
                            break
                        done, _ = await asyncio.wait(
                            [read_task], timeout=self.settings.poll_seconds
                        )
                        if not done:
                            continue
                        frame = read_task.result()
                        stdout.append(frame.stdout)
                        stderr.append(frame.stderr)
                        if frame.exit_code is not None:
                            code = frame.exit_code
                            exited = True
                            break
                        read_task = asyncio.create_task(process.read())
        except TimeoutError:
            error = "execution timed out"
        except asyncio.CancelledError:
            error = "execution interrupted"
            raise
        except Exception:
            error = "guest execution failed"
        finally:
            if read_task is not None:
                read_task.cancel()
                await asyncio.gather(read_task, return_exceptions=True)
            try:
                async with asyncio.timeout(self.settings.control_seconds):
                    if not exited:
                        # Also covers start failure or crash before the PVC write.
                        pid = pid or await self.kube.read_pid(pod)
                        if pid is not None:
                            self.store.save(request.execution_id, GuestPid(pod.uid, pid))
                            await self.kube.kill_tree(pod, pid)
                    # Success deliberately does NOT reap surviving background work.
                    await self.kube.clear_pid(pod)
                    self.store.remove(request.execution_id)
                    self.clean = True
            except Exception:
                error = "guest cleanup failed"
                # Retain the PVC entry for restart recovery and reject subsequent execution.
            finally:
                if process is not None:
                    try:
                        await process.close()
                    except Exception:
                        error = error or "guest stream close failed"
        return SandboxResult(
            request.execution_id,
            code,
            stdout.text(),
            stderr.text(),
            stdout.truncated or stderr.truncated,
            int((time.monotonic() - started) * 1000),
            bool(error),
            error,
        )
