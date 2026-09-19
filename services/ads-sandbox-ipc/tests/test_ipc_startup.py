from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from ads_commons.sandbox import (
    SandboxIpcError,
    SandboxReady,
    SandboxShutdown,
    SandboxShutdownAck,
)
from ads_sandbox_ipc.controller import READY_TOPIC
from ads_sandbox_ipc.pid_store import GuestPid, PidStore
from ipc_support import Harness, eventually


@pytest.mark.anyio
async def test_startup_reaps_pvc_and_guest_file_before_ping(ipc) -> None:
    ipc.store.save(uuid4(), GuestPid(ipc.kube.pod.uid, 71))
    ipc.kube.pid = 72  # crashed before PVC write
    async with ipc.running():
        assert ipc.kube.killed == [(ipc.kube.pod, 71), (ipc.kube.pod, 72)]
        assert not ipc.store.entries()
        assert ipc.kube.calls == [(ipc.kube.pod, ["ads-session-exec", "shell", "true"], b"")]
        assert ipc.publisher.messages == [SandboxReady(ipc.settings.sandbox_id)]
        assert ipc.publisher.subject_tokens == [None]  # client credentials, not STE
        assert ipc.service.http_ready


@pytest.mark.anyio
async def test_pid_from_old_pod_namespace_is_not_killed_in_replacement(ipc) -> None:
    ipc.store.save(uuid4(), GuestPid("deleted-pod-uid", 420))
    async with ipc.running():
        assert not ipc.kube.killed and not ipc.store.entries()


@pytest.mark.anyio
@pytest.mark.parametrize("phase", ["pod", "reap", "ping", "kube", "store"])
async def test_startup_timeout_emits_one_error_never_ready_and_stays_live(tmp_path, phase) -> None:
    ipc = Harness(tmp_path, startup_seconds=0.08)
    if phase == "pod":
        ipc.kube.ready = False
    elif phase == "reap":
        ipc.kube.pid = 77
        ipc.kube.fail_kill = True
    elif phase == "ping":
        ipc.kube.ping_exit = 1
    elif phase == "kube":
        ipc.kube.fail_prepare = True
    else:
        (tmp_path / f"{uuid4()}.json").write_text("corrupted")
    async with ipc.running(boot=False):
        await eventually(lambda: ipc.service.failed)
        assert len(ipc.publisher.messages) == 1
        assert isinstance(ipc.publisher.messages[0], SandboxIpcError)
        assert not ipc.service.http_ready and not ipc.service.kafka_ready
        ipc.kube.ready = True
        ipc.kube.fail_kill = ipc.kube.fail_prepare = False
        ipc.kube.ping_exit = 0
        await ipc.send(ipc.request())
        assert len(ipc.publisher.messages) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("phase", ["pod", "ready-publication"])
async def test_shutdown_wins_during_startup(ipc, phase) -> None:
    if phase == "pod":
        ipc.kube.pause_ready.clear()
    else:
        ipc.publisher.block_type = SandboxReady
    async with ipc.running(boot=False):
        if phase == "ready-publication":
            await ipc.publisher.blocked.wait()
        else:
            await eventually(lambda: ipc.kube.polls > 0)
        await ipc.send(SandboxShutdown(ipc.settings.sandbox_id), topic=READY_TOPIC)
        ipc.kube.pause_ready.set()
        ipc.publisher.release.set()
        assert ipc.publisher.messages == [SandboxShutdownAck(ipc.settings.sandbox_id)]
        assert not ipc.service.failed and not ipc.service.kafka_ready


def test_pid_store_is_durable_atomic_and_contains_only_pid_identity(ipc) -> None:
    execution_id = uuid4()
    entry = GuestPid("pod-uid", 431)
    ipc.store.save(execution_id, entry)
    restarted = PidStore(ipc.settings)
    assert restarted.entries() == [(execution_id, entry)]
    files = list(ipc.settings.pid_directory.iterdir())
    assert len(files) == 1
    assert files[0].stat().st_mode & 0o777 == 0o600
    assert files[0].read_text() == '{"pod_uid": "pod-uid", "pid": 431}'
    restarted.remove(execution_id)
    restarted.remove(execution_id)
    assert not restarted.entries()


@pytest.mark.parametrize("pid", [0, 1, -1, True, "42"])
def test_pid_store_rejects_unsafe_numbers(pid) -> None:
    with pytest.raises(ValueError):
        GuestPid("pod", pid)


@pytest.mark.parametrize(
    "changes",
    [
        {"stdout_bytes": 0},
        {"input_bytes": -1},
        {"ack_seconds": 0},
        {"timeout_seconds": float("nan")},
        {"startup_seconds": float("inf")},
        {"namespace": "../other"},
    ],
)
def test_configuration_fails_closed(ipc, changes) -> None:
    with pytest.raises(ValueError):
        replace(ipc.settings, **changes)
