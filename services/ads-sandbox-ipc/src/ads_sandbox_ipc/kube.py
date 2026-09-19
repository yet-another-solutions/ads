from __future__ import annotations

import asyncio
import json
import ssl
from typing import Any
from urllib.parse import quote, urlencode

from kubernetes import client, config
from websockets.asyncio.client import ClientConnection, connect
from websockets.typing import Subprotocol

from ads_sandbox_ipc.config import Settings
from ads_sandbox_ipc.guest import CappedOutput, Frame, Pod, Process

PID_FILE = "/run/ads-session-exec.pid"

# Freeze before descending so the selected tree cannot fork out of the walk.
# /proc and bash builtins only: the immutable guest does not require procps.
# No process-group, user-wide, Podman-wide, or container-wide kill.
KILL_TREE = r"""
set -eu
reap() {
    local pid=$1 children='' child
    [[ -d /proc/$pid ]] || return 0
    if ! kill -STOP -- "$pid" 2>/dev/null; then
        [[ ! -d /proc/$pid ]] && return 0
        return 1
    fi
    if [[ -r /proc/$pid/task/$pid/children ]]; then
        read -r children <"/proc/$pid/task/$pid/children" || true
    fi
    for child in $children; do reap "$child"; done
    if ! kill -KILL -- "$pid" 2>/dev/null; then
        [[ ! -d /proc/$pid ]] || return 1
    fi
}
[[ $1 =~ ^[0-9]+$ && $1 -gt 1 && $1 -ne $$ ]] || exit 1
reap "$1"
"""


class KubeProcess:
    """Kubernetes v5 channels with explicit stdin EOF and bounded WebSocket frames."""

    def __init__(self, websocket: ClientConnection) -> None:
        self.websocket = websocket

    async def read(self) -> Frame:
        while True:
            data = await self.websocket.recv()
            if not isinstance(data, bytes) or not data:
                raise RuntimeError("invalid Kubernetes exec frame")
            channel, body = data[0], data[1:]
            if channel == 1:
                return Frame(stdout=body)
            if channel == 2:
                return Frame(stderr=body)
            if channel == 3:
                status = json.loads(body)
                if status.get("status") == "Success":
                    return Frame(exit_code=0)
                if status.get("reason") == "NonZeroExitCode":
                    for cause in status.get("details", {}).get("causes", []):
                        if cause.get("reason") == "ExitCode":
                            return Frame(exit_code=int(cause["message"]))
                raise RuntimeError("Kubernetes exec failed")
            if channel == 255:
                continue
            raise RuntimeError("unexpected Kubernetes exec channel")

    async def close(self) -> None:
        await self.websocket.close()


class KubeClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.configuration = client.Configuration()
        # Only the projected pod identity. No kubeconfig or ambient developer credentials.
        config.load_incluster_config(client_configuration=self.configuration)
        if not self.configuration.host.startswith("https://") or not self.configuration.verify_ssl:
            raise ValueError("Kubernetes requires verified HTTPS")
        self.api_client = client.ApiClient(self.configuration)
        self.api = client.CoreV1Api(self.api_client)
        self.ssl = ssl.create_default_context(cafile=self.configuration.ssl_ca_cert)

    def _matches(self, item: Any) -> bool:
        return (
            item.metadata.deletion_timestamp is None
            and (item.metadata.labels or {}).get("ads.io/sandbox-id")
            == str(self.settings.sandbox_id)
            and any(container.name == "sandbox" for container in item.spec.containers)
        )

    async def ready_pod(self) -> Pod | None:
        result = await asyncio.to_thread(
            self.api.list_namespaced_pod,
            self.settings.namespace,
            label_selector=self.settings.selector,
            _request_timeout=self.settings.control_seconds,
        )
        candidates = [item for item in result.items if self._matches(item)]
        if len(candidates) != 1:
            return None
        item = candidates[0]
        if not any(
            condition.type == "Ready" and condition.status == "True"
            for condition in item.status.conditions or []
        ):
            return None
        return Pod(item.metadata.name, item.metadata.uid)

    async def start(self, pod: Pod, argv: list[str], stdin: bytes) -> Process:
        item = await asyncio.to_thread(
            self.api.read_namespaced_pod,
            pod.name,
            self.settings.namespace,
            _request_timeout=self.settings.control_seconds,
        )
        if not self._matches(item) or item.metadata.uid != pod.uid:
            raise RuntimeError("sandbox pod identity changed")
        # The SDK refreshes the projected token here; never send a Keycloak JWT to kube.
        authorization = self.configuration.get_api_key_with_prefix(
            "BearerToken", alias="authorization"
        )
        if not authorization:
            raise RuntimeError("Kubernetes projected service account token is unavailable")
        query: list[tuple[str, str]] = [
            ("container", "sandbox"),
            ("stdin", "true"),
            ("stdout", "true"),
            ("stderr", "true"),
            ("tty", "false"),
            *(("command", value) for value in argv),
        ]
        url = (
            self.configuration.host.replace("https://", "wss://", 1).rstrip("/")
            + f"/api/v1/namespaces/{quote(self.settings.namespace, safe='')}"
            + f"/pods/{quote(pod.name, safe='')}/exec?{urlencode(query)}"
        )
        websocket = await connect(
            url,
            ssl=self.ssl,
            additional_headers={"Authorization": authorization},
            subprotocols=[Subprotocol("v5.channel.k8s.io")],
            open_timeout=self.settings.control_seconds,
            close_timeout=1,
            max_size=1024 * 1024,
            max_queue=4,
            proxy=None,
        )
        try:
            if websocket.subprotocol != "v5.channel.k8s.io":
                raise RuntimeError("Kubernetes v5 stdin EOF is required")
            for offset in range(0, len(stdin), 16384):
                await websocket.send(b"\x00" + stdin[offset : offset + 16384])
            await websocket.send(b"\xff\x00")
        except BaseException:
            await websocket.close()
            raise
        return KubeProcess(websocket)

    async def _control(self, pod: Pod, argv: list[str]) -> tuple[int, bytes, bytes]:
        stdout, stderr = CappedOutput(4096), CappedOutput(4096)
        process: Process | None = None
        try:
            async with asyncio.timeout(self.settings.control_seconds):
                process = await self.start(pod, argv, b"")
                while True:
                    frame = await process.read()
                    stdout.append(frame.stdout)
                    stderr.append(frame.stderr)
                    if stdout.truncated or stderr.truncated:
                        raise RuntimeError("unexpected control output size")
                    if frame.exit_code is not None:
                        return frame.exit_code, bytes(stdout.data), bytes(stderr.data)
        finally:
            if process is not None:
                await process.close()

    async def read_pid(self, pod: Pod) -> int | None:
        # A separate cat-only exec, never attached to the session process's streams.
        code, stdout, stderr = await self._control(pod, ["cat", PID_FILE])
        if code == 1 and not stdout and b"No such file or directory" in stderr:
            return None
        if code != 0:
            raise RuntimeError("guest pid read failed")
        value = stdout.strip()
        if not value.isdigit() or int(value) <= 1:
            raise RuntimeError("invalid guest pid")
        return int(value)

    async def kill_tree(self, pod: Pod, pid: int) -> None:
        if type(pid) is not int or pid <= 1:
            raise ValueError("unsafe guest pid")
        code, _, _ = await self._control(
            pod, ["/bin/bash", "--noprofile", "--norc", "-c", KILL_TREE, "ads-ipc-reap", str(pid)]
        )
        if code != 0:
            raise RuntimeError("guest process tree reap failed")

    async def clear_pid(self, pod: Pod) -> None:
        code, _, _ = await self._control(pod, ["rm", "-f", PID_FILE])
        if code != 0:
            raise RuntimeError("guest pid clear failed")

    async def close(self) -> None:
        await asyncio.to_thread(self.api_client.close)
