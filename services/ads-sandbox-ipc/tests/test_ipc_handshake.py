from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from ads_commons.sandbox import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxPing,
    SandboxResult,
    SandboxShutdown,
    SandboxShutdownAck,
)
from ads_sandbox_ipc.controller import PING_REQUEST_TOPIC, READY_TOPIC
from ads_sandbox_ipc.guest import Frame
from ipc_support import Harness, eventually

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    "kind,payload", [("shell", "echo hello | cat"), ("python", "print('hello')")]
)
async def test_ack_boundary_pid_and_result(ipc, kind, payload) -> None:
    async with ipc.running():
        request = ipc.request(kind, payload)
        request_token = await ipc.send(request)
        assert ipc.publisher.messages[-1] == SandboxAcknowledge(
            request.execution_id, request.session_id, request.message_id
        )
        assert ipc.publisher.subject_tokens[-1] == request_token
        assert len(ipc.kube.calls) == 1  # startup true only
        ack_token = await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        await eventually(lambda: bool(ipc.store.entries()))
        _, argv, stdin = ipc.kube.calls[-1]
        assert argv == ["ads-session-exec", kind] + ([payload] if kind == "shell" else [])
        assert stdin == (payload.encode() if kind == "python" else b"")
        assert ipc.store.entries()[0][0] == request.execution_id
        ipc.finish(7, b"hello", b"warning")
        await eventually(lambda: isinstance(ipc.publisher.messages[-1], SandboxResult))
        result = ipc.publisher.messages[-1]
        assert (result.exit_code, result.stdout, result.stderr, result.is_error) == (
            7,
            "hello",
            "warning",
            False,
        )
        assert ipc.publisher.subject_tokens[-1] == ack_token != request_token
        assert not ipc.store.entries() and ipc.kube.pid is None
        assert not ipc.kube.killed  # normal completion preserves background work
        assert ipc.kube.processes[-1].closed


@pytest.mark.parametrize("control", [SandboxAckReset, SandboxAbort, None])
async def test_reset_abort_or_ack_timeout_never_executes(ipc, control) -> None:
    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        if control:
            await ipc.send(control(request.execution_id, request.session_id, request.message_id))
        await eventually(lambda: ipc.service.current is None)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        await ipc.send(request)
        assert len(ipc.kube.calls) == 1
        assert not any(isinstance(m, SandboxResult) for m in ipc.publisher.messages)
        assert not ipc.kube.killed


async def test_current_and_one_last_result_are_idempotent(ipc) -> None:
    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        await ipc.send(request)
        assert len([m for m in ipc.publisher.messages if isinstance(m, SandboxAcknowledge)]) == 2
        await ipc.send(ipc.request())  # busy: no second unit
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        await eventually(lambda: len(ipc.kube.calls) == 2)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        await ipc.send(request)
        ipc.finish(stdout=b"once")
        await eventually(lambda: ipc.service.last_result is not None)
        result = ipc.service.last_result
        await ipc.send(request)
        assert ipc.publisher.messages[-1] == result
        assert len(ipc.kube.calls) == 2


async def test_abort_only_current_execution_and_ping_is_not_serialized(ipc) -> None:
    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        await eventually(lambda: bool(ipc.store.entries()))
        await ipc.send(
            SandboxAbort(ipc.request().execution_id, request.session_id, request.message_id)
        )
        assert not ipc.kube.killed
        ping = SandboxPing(ipc.request().execution_id, ipc.settings.sandbox_id)
        ping_token = await ipc.send(ping, topic=PING_REQUEST_TOPIC)
        assert ipc.publisher.messages[-1] == ping
        assert ipc.publisher.subject_tokens[-1] == ping_token
        assert len(ipc.kube.calls) == 2  # ping is ipc-alive, not a guest exec
        await ipc.send(
            SandboxAckReset(request.execution_id, request.session_id, request.message_id)
        )  # too late to reset
        assert not ipc.kube.killed
        await ipc.send(SandboxAbort(request.execution_id, request.session_id, request.message_id))
        await eventually(lambda: ipc.service.last_result is not None)
        assert ipc.service.last_result.is_error
        assert ipc.service.last_result.text == "execution aborted"
        assert ipc.kube.killed == [(ipc.kube.pod, 420)]
        assert not ipc.store.entries()


async def test_shutdown_finishes_then_acks_and_repeated_shutdown_acks_again(ipc) -> None:
    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        await eventually(lambda: len(ipc.kube.calls) == 2)
        shutdown = SandboxShutdown(ipc.settings.sandbox_id, datetime.now(UTC))
        token = await ipc.send(shutdown, topic=READY_TOPIC)
        count = len(ipc.publisher.messages)
        await ipc.send(ipc.request())
        await ipc.send(
            SandboxPing(request.execution_id, ipc.settings.sandbox_id), topic=PING_REQUEST_TOPIC
        )
        assert len(ipc.publisher.messages) == count
        assert not ipc.kube.killed
        ipc.finish(stdout=b"finished")
        await eventually(lambda: isinstance(ipc.publisher.messages[-1], SandboxShutdownAck))
        assert isinstance(ipc.publisher.messages[-2], SandboxResult)
        assert ipc.publisher.subject_tokens[-1] == token
        assert ipc.publisher.messages[-1].transition == shutdown.transition
        assert ipc.service.http_ready  # readiness latches, never an exec/guest-alive probe
        second_token = await ipc.send(shutdown, topic=READY_TOPIC)
        assert isinstance(ipc.publisher.messages[-1], SandboxShutdownAck)
        assert isinstance(ipc.publisher.messages[-2], SandboxShutdownAck)
        assert ipc.publisher.subject_tokens[-1] == second_token
        assert ipc.publisher.messages[-1].transition == shutdown.transition


async def test_shutdown_drops_waiter(ipc) -> None:
    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        await ipc.send(SandboxShutdown(ipc.settings.sandbox_id), topic=READY_TOPIC)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        assert len(ipc.kube.calls) == 1
        assert isinstance(ipc.publisher.messages[-1], SandboxShutdownAck)


async def test_output_caps_drain_until_exit_and_timeout_kills_only_tree(tmp_path) -> None:
    ipc = Harness(tmp_path, stdout_bytes=5, stderr_bytes=3, timeout_seconds=0.15)
    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        await eventually(lambda: bool(ipc.store.entries()))
        process = ipc.kube.processes[-1]
        for _ in range(40):
            process.frames.put_nowait(Frame(stdout=b"abcdef", stderr=b"12345"))
        await eventually(lambda: process.reads == 40)
        assert not ipc.kube.killed and ipc.service.last_result is None
        await eventually(lambda: ipc.service.last_result is not None)
        result = ipc.service.last_result
        assert (result.stdout, result.stderr, result.truncated, result.is_error) == (
            "abcde",
            "123",
            True,
            True,
        )
        assert result.text == "execution timed out"
        assert ipc.kube.killed == [(ipc.kube.pod, 420)]
        assert not ipc.store.entries()


@pytest.mark.parametrize("kind", ["shell", "python"])
async def test_input_cap_is_utf8_bytes_and_never_executes(tmp_path, kind) -> None:
    ipc = Harness(tmp_path, input_bytes=4)
    async with ipc.running():
        request = ipc.request(kind, "€€")
        await ipc.send(request)
        result = ipc.publisher.messages[-1]
        assert isinstance(result, SandboxResult) and result.is_error
        assert result.text == "input limit exceeded"
        assert len(ipc.kube.calls) == 1
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        assert len(ipc.kube.calls) == 1


async def test_failed_result_send_can_retry_but_never_reexecute(ipc) -> None:
    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        await eventually(lambda: len(ipc.kube.calls) == 2)
        ipc.publisher.fail_type = SandboxResult
        ipc.finish()
        await eventually(lambda: ipc.service.last_result is not None)
        assert not ipc.service._result_delivered
        await ipc.send(SandboxShutdown(ipc.settings.sandbox_id), topic=READY_TOPIC)
        assert not isinstance(ipc.publisher.messages[-1], SandboxShutdownAck)
        ipc.publisher.fail_type = None
        await ipc.send(SandboxShutdown(ipc.settings.sandbox_id), topic=READY_TOPIC)
        assert ipc.service._result_delivered
        assert isinstance(ipc.publisher.messages[-1], SandboxShutdownAck)
        assert len(ipc.kube.calls) == 2


async def test_short_ack_ttl_warns_and_still_executes(ipc, ipc_logs) -> None:
    ipc.settings = replace(ipc.settings, timeout_seconds=3)
    ipc.service.settings = ipc.settings
    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id),
            ipc.keys.token(exp=int(time.time()) + 2),
        )
        await eventually(lambda: len(ipc.kube.calls) == 2)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id),
            ipc.keys.token(exp=int(time.time()) + 2),
        )
        ipc.finish()
        await eventually(lambda: ipc.service.last_result is not None)
        assert (
            sum(
                entry["event"] == "ack_reply_ttl_below_exec_timeout"
                and entry["log_level"] == "warning"
                for entry in ipc_logs
            )
            == 2
        )
        assert len(ipc.kube.calls) == 2


async def test_shutdown_cancels_inflight_ping_publication(ipc) -> None:
    async with ipc.running():
        ipc.publisher.block_type = SandboxPing
        task = asyncio.create_task(
            ipc.send(
                SandboxPing(ipc.request().execution_id, ipc.settings.sandbox_id),
                topic=PING_REQUEST_TOPIC,
            )
        )
        await ipc.publisher.blocked.wait()
        await ipc.send(SandboxShutdown(ipc.settings.sandbox_id), topic=READY_TOPIC)
        ipc.publisher.release.set()
        await asyncio.gather(task, return_exceptions=True)
        assert not any(isinstance(m, SandboxPing) for m in ipc.publisher.messages)
