from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlparse

import pytest
from kubernetes.client import Configuration

from ads_sandbox_ipc.guest import CappedOutput, Frame, Pod
from ads_sandbox_ipc.kube import PID_FILE, KubeClient, KubeProcess
from ipc_support import eventually


def pod_object(ipc):
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name="actual-replica",
            uid="pod-uid",
            deletion_timestamp=None,
            labels={"ads.io/sandbox-id": str(ipc.settings.sandbox_id)},
        ),
        spec=SimpleNamespace(containers=[SimpleNamespace(name="sandbox")]),
        status=SimpleNamespace(conditions=[SimpleNamespace(type="Ready", status="True")]),
    )


@pytest.fixture
def kube(ipc, monkeypatch):
    monkeypatch.setattr("ads_sandbox_ipc.kube.config.load_incluster_config", Mock())
    configuration = Mock(
        host="https://kube.test",
        verify_ssl=True,
        ssl_ca_cert=None,
        get_api_key_with_prefix=Mock(return_value="Bearer projected-sa-token"),
    )
    monkeypatch.setattr(
        "ads_sandbox_ipc.kube.client.Configuration", Mock(return_value=configuration)
    )
    monkeypatch.setattr("ads_sandbox_ipc.kube.client.ApiClient", Mock())
    monkeypatch.setattr("ads_sandbox_ipc.kube.client.CoreV1Api", Mock())
    kube = KubeClient(ipc.settings)
    kube.api.list_namespaced_pod.return_value = SimpleNamespace(items=[pod_object(ipc)])
    kube.api.read_namespaced_pod.return_value = pod_object(ipc)
    return kube


@pytest.mark.anyio
async def test_ready_selects_actual_labeled_replica_not_deployment(kube, ipc) -> None:
    assert await kube.ready_pod() == Pod("actual-replica", "pod-uid")
    assert kube.api.list_namespaced_pod.call_args.kwargs["label_selector"] == ipc.settings.selector
    item = pod_object(ipc)
    item.status.conditions[0].status = "False"
    kube.api.list_namespaced_pod.return_value.items = [item]
    assert await kube.ready_pod() is None
    kube.api.list_namespaced_pod.return_value.items = [pod_object(ipc), pod_object(ipc)]
    assert await kube.ready_pod() is None
    kube.api.list_namespaced_pod.return_value.items = []
    assert await kube.ready_pod() is None


@pytest.mark.anyio
async def test_kube_v5_stdin_eof_and_no_tty_or_keycloak_token(kube, monkeypatch) -> None:
    socket = SimpleNamespace(subprotocol="v5.channel.k8s.io", send=AsyncMock(), close=AsyncMock())
    connect = AsyncMock(return_value=socket)
    monkeypatch.setattr("ads_sandbox_ipc.kube.connect", connect)
    process = await kube.start(
        Pod("actual-replica", "pod-uid"), ["ads-session-exec", "python"], b"x=1"
    )
    url = connect.call_args.args[0]
    query = parse_qs(urlparse(url).query)
    assert query["command"] == ["ads-session-exec", "python"]
    assert query["container"] == ["sandbox"] and query["tty"] == ["false"]
    assert query["stdin"] == ["true"] and query["stderr"] == query["stdout"] == ["true"]
    assert connect.call_args.kwargs["additional_headers"] == {
        "Authorization": "Bearer projected-sa-token"
    }
    assert connect.call_args.kwargs["proxy"] is None
    assert [call.args[0] for call in socket.send.call_args_list] == [b"\x00x=1", b"\xff\x00"]
    kube.configuration.get_api_key_with_prefix.assert_called_once_with(
        "BearerToken", alias="authorization"
    )
    await process.close()
    socket.close.assert_awaited_once()


@pytest.mark.anyio
@pytest.mark.parametrize("key", ["BearerToken", "authorization"])
async def test_exec_uses_real_sdk_token_lookup_and_rotation(kube, monkeypatch, key) -> None:
    configuration = Configuration(host="https://kube.test")
    # InClusterConfigLoader stores the complete bearer value, not a separate prefix.
    configuration.api_key[key] = "bearer stale-projected-token"
    tokens = iter(["bearer first-projected-token", "bearer rotated-projected-token"])

    def refresh(current):
        current.api_key[key] = next(tokens)

    configuration.refresh_api_key_hook = Mock(side_effect=refresh)
    kube.configuration = configuration
    socket = SimpleNamespace(subprotocol="v5.channel.k8s.io", send=AsyncMock(), close=AsyncMock())
    connect = AsyncMock(return_value=socket)
    monkeypatch.setattr("ads_sandbox_ipc.kube.connect", connect)
    for expected in ["bearer first-projected-token", "bearer rotated-projected-token"]:
        process = await kube.start(Pod("actual-replica", "pod-uid"), ["true"], b"")
        assert connect.call_args.kwargs["additional_headers"] == {"Authorization": expected}
        await process.close()
    assert configuration.refresh_api_key_hook.call_count == 2


@pytest.mark.anyio
async def test_exec_prefers_current_sdk_key_over_legacy_alias(kube, monkeypatch) -> None:
    configuration = Configuration(host="https://kube.test")
    configuration.api_key = {
        "BearerToken": "bearer current-projected-token",
        "authorization": "bearer stale-legacy-token",
    }
    kube.configuration = configuration
    socket = SimpleNamespace(subprotocol="v5.channel.k8s.io", send=AsyncMock(), close=AsyncMock())
    connect = AsyncMock(return_value=socket)
    monkeypatch.setattr("ads_sandbox_ipc.kube.connect", connect)
    process = await kube.start(Pod("actual-replica", "pod-uid"), ["true"], b"")
    assert connect.call_args.kwargs["additional_headers"] == {
        "Authorization": "bearer current-projected-token"
    }
    await process.close()


@pytest.mark.anyio
@pytest.mark.parametrize("token", [None, ""])
async def test_missing_projected_token_fails_before_websocket(kube, monkeypatch, token) -> None:
    configuration = Configuration(host="https://kube.test")
    if token is not None:
        configuration.api_key["BearerToken"] = token
    kube.configuration = configuration
    connect = AsyncMock()
    monkeypatch.setattr("ads_sandbox_ipc.kube.connect", connect)
    with pytest.raises(RuntimeError, match="projected service account token is unavailable"):
        await kube.start(Pod("actual-replica", "pod-uid"), ["true"], b"")
    connect.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("change", ["uid", "label", "deleting", "container"])
async def test_each_exec_rechecks_target_identity(kube, change, monkeypatch) -> None:
    item = kube.api.read_namespaced_pod.return_value
    if change == "uid":
        item.metadata.uid = "replacement"
    elif change == "label":
        item.metadata.labels = {"ads.io/sandbox-id": "other"}
    elif change == "deleting":
        item.metadata.deletion_timestamp = "now"
    else:
        item.spec.containers = [SimpleNamespace(name="wrong")]
    connect = AsyncMock()
    monkeypatch.setattr("ads_sandbox_ipc.kube.connect", connect)
    with pytest.raises(RuntimeError, match="identity changed"):
        await kube.start(
            Pod("actual-replica", "pod-uid"), ["ads-session-exec", "shell", "true"], b""
        )
    connect.assert_not_awaited()


@pytest.mark.anyio
async def test_v4_is_rejected_and_socket_closed(kube, monkeypatch) -> None:
    socket = SimpleNamespace(subprotocol="v4.channel.k8s.io", close=AsyncMock())
    monkeypatch.setattr("ads_sandbox_ipc.kube.connect", AsyncMock(return_value=socket))
    with pytest.raises(RuntimeError, match="stdin EOF"):
        await kube.start(Pod("actual-replica", "pod-uid"), ["cat"], b"")
    socket.close.assert_awaited_once()


@pytest.mark.anyio
async def test_channels_and_nonzero_exit_are_not_protocol_errors() -> None:
    status = {
        "status": "Failure",
        "reason": "NonZeroExitCode",
        "details": {"causes": [{"reason": "ExitCode", "message": "23"}]},
    }
    socket = SimpleNamespace(
        recv=AsyncMock(
            side_effect=[b"\x01out", b"\x02err", b"\xff\x01", b"\x03" + json.dumps(status).encode()]
        )
    )
    process = KubeProcess(socket)
    assert await process.read() == Frame(stdout=b"out")
    assert await process.read() == Frame(stderr=b"err")
    assert await process.read() == Frame(exit_code=23)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "frame", [b"", "text", b"\x06wrong", b'\x03{"status":"Failure","reason":"Forbidden"}']
)
async def test_broken_stream_status_is_not_a_success(frame) -> None:
    process = KubeProcess(SimpleNamespace(recv=AsyncMock(return_value=frame)))
    with pytest.raises(RuntimeError):
        await process.read()


@pytest.mark.anyio
async def test_cat_only_pid_read_absence_and_error_discrimination(kube) -> None:
    pod = Pod("actual-replica", "pod-uid")
    kube._control = AsyncMock(return_value=(0, b"42\n", b""))
    assert await kube.read_pid(pod) == 42
    kube._control.assert_awaited_once_with(pod, ["cat", PID_FILE])
    kube._control.return_value = (
        1,
        b"",
        b"cat: /run/ads-session-exec.pid: No such file or directory",
    )
    assert await kube.read_pid(pod) is None
    kube._control.return_value = (1, b"", b"Permission denied")
    with pytest.raises(RuntimeError):
        await kube.read_pid(pod)
    kube._control.return_value = (0, b"1", b"")
    with pytest.raises(RuntimeError):
        await kube.read_pid(pod)


@pytest.mark.anyio
async def test_cleanup_failure_retains_pid_and_prevents_next_exec(ipc) -> None:
    from ads_commons.sandbox import SandboxAbort, SandboxAckReply

    async with ipc.running():
        request = ipc.request()
        await ipc.send(request)
        await ipc.send(
            SandboxAckReply(request.execution_id, request.session_id, request.message_id)
        )
        await eventually(lambda: bool(ipc.store.entries()))
        ipc.kube.fail_kill = True
        await ipc.send(SandboxAbort(request.execution_id, request.session_id, request.message_id))
        await eventually(lambda: ipc.service.last_result is not None)
        assert ipc.store.entries()[0][1].pid == 420
        assert not ipc.guest.clean
        assert ipc.service.last_result.text == "guest cleanup failed"
        second = ipc.request()
        await ipc.send(second)
        await ipc.send(SandboxAckReply(second.execution_id, second.session_id, second.message_id))
        await eventually(lambda: ipc.service.last_id == second.execution_id)
        assert len(ipc.kube.calls) == 2
        assert ipc.service.last_result.is_error
        assert ipc.store.entries()[0][1].pid == 420


def test_utf8_caps_do_not_expand_or_corrupt_a_split_codepoint() -> None:
    output = CappedOutput(5)
    for chunk in [b"\xe2", b"\x82\xac", b"\xe2\x82", b"\xac"]:
        output.append(chunk)
    assert output.text() == "€"
    assert len(output.data) == 5
    assert len(output.text().encode()) <= 5
    assert output.truncated
