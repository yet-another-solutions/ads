"""Authenticated, bounded delivery to the node-owner pod on the original node."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx2
import msgspec

from ads_commons.sandbox.block_release import BlockReleaseReport, decode_block_release
from ads_commons.sandbox.ipc_release import IpcReleaseReport, decode_ipc_release
from ads_commons.sandbox.ipc_storage import (
    IpcStorageReport,
    UnusedIpcStorageReport,
    decode_ipc_storage,
    decode_unused_ipc_storage,
)
from ads_commons.sandbox.node_release import NodeReleaseReport, _unique, decode_node_release
from ads_commons.sandbox.partial_release import PartialReleaseReport, decode_partial_release
from ads_sandbox_manager.pair_objects import PairBinding

LIMIT = 32768
SCHEMA = "ads-node-owner-v1"


@dataclass(frozen=True)
class NodeOwnerSettings:
    namespace: str
    network: str
    ca: Path
    certificate: Path
    key: Path = field(repr=False)
    timeout: float = 60
    server_cn: str = "ads-node-owner"

    def __post_init__(self) -> None:
        if (
            not self.namespace.strip()
            or not self.network.strip()
            or not self.server_cn.strip()
            or not math.isfinite(self.timeout)
            or not 0 < self.timeout <= 70
        ):
            raise ValueError("bounded explicit node-owner configuration required")
        if not all(path.is_absolute() for path in (self.ca, self.certificate, self.key)):
            raise ValueError("absolute node TLS credential paths required")

    @classmethod
    def parse(cls, value: dict[str, Any]) -> NodeOwnerSettings:
        if not isinstance(value, dict) or set(value) != {
            "namespace",
            "network",
            "ca",
            "certificate",
            "key",
            "timeout",
        }:
            raise ValueError("exact node-owner configuration required")
        if not all(
            isinstance(value[k], str) for k in ("namespace", "network", "ca", "certificate", "key")
        ) or type(value["timeout"]) not in (int, float):
            raise ValueError("invalid node-owner configuration types")
        return cls(
            namespace=value["namespace"],
            network=value["network"],
            ca=Path(value["ca"]),
            certificate=Path(value["certificate"]),
            key=Path(value["key"]),
            timeout=value["timeout"],
        )

    def context(self) -> ssl.SSLContext:
        # A dedicated CA, not the ambient public trust store. Client key is
        # loaded before accepting application work and never sent in JSON.
        context = ssl.create_default_context(cafile=str(self.ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_cert_chain(str(self.certificate), str(self.key))
        return context


class NodeOwnerDirectory:
    """Node name to the one Ready node-owner pod IP. Not a settings field."""

    def __init__(self, kube: Any, namespace: str) -> None:
        self.kube = kube
        self.namespace = namespace
        self.addresses: dict[str, str] = {}

    async def refresh(self) -> None:
        pods = await self.kube._list(
            self.kube.core.list_namespaced_pod,
            self.namespace,
            label_selector="app.kubernetes.io/component=ads-node-owner",
        )
        found: dict[str, str] = {}
        failed: set[str] = set()
        for pod in pods:
            spec, status = pod.get("spec", {}), pod.get("status", {})
            node = spec.get("nodeName")
            ready = any(
                item.get("type") == "Ready" and item.get("status") == "True"
                for item in status.get("conditions", [])
            )
            address = status.get("podIP")
            if (
                not isinstance(node, str)
                or not ready
                or not isinstance(address, str)
                or not address
            ):
                if isinstance(node, str):
                    failed.add(node)
                continue
            if node in found:
                failed.add(node)
                found.pop(node, None)
                continue
            found[node] = address
        for node in failed:
            found.pop(node, None)
        self.addresses = found


def peer_cn(certificate: dict[str, Any]) -> str:
    subject = certificate.get("subject", ())
    names = [value for item in subject for key, value in item if key == "commonName"]
    if len(names) != 1:
        raise ValueError("node-owner server CN required")
    return names[0]


def cn_transport(context: ssl.SSLContext, expected: str) -> httpx2.AsyncHTTPTransport:
    """Reject a wrong server CN during the handshake, before the HTTP body."""
    import httpcore2
    from httpcore2._backends.anyio import AnyIOBackend

    class Stream:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        async def start_tls(
            self,
            ssl_context: ssl.SSLContext,
            server_hostname: str | None = None,
            timeout: float | None = None,
        ):
            stream = await self._inner.start_tls(ssl_context, server_hostname, timeout)
            certificate = stream.get_extra_info("ssl_object").getpeercert()
            if peer_cn(certificate) != expected:
                await stream.aclose()
                raise ValueError("unexpected node-owner server")
            return stream

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    class Backend(AnyIOBackend):
        async def connect_tcp(self, *args: Any, **kwargs: Any) -> Any:
            return Stream(await super().connect_tcp(*args, **kwargs))

    transport = httpx2.AsyncHTTPTransport(verify=context, retries=0, http2=False)
    transport._pool = httpcore2.AsyncConnectionPool(
        ssl_context=context,
        max_connections=4,
        max_keepalive_connections=0,
        retries=0,
        http2=False,
        network_backend=Backend(),
    )
    return transport


class HttpsNodeOwner:
    def __init__(
        self,
        settings: NodeOwnerSettings,
        context: ssl.SSLContext,
        addresses: dict[str, str],
        *,
        port: int = 9443,
    ) -> None:
        # Pod IP is the dial address. The lab CA plus the server CN is the check.
        if context.verify_mode != ssl.CERT_REQUIRED or context.check_hostname:
            raise ValueError("lab-root TLS without hostname-as-IP check required")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("node-owner port required")
        self.settings = settings
        self.addresses = addresses
        self.port = port
        self.client = httpx2.AsyncClient(
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=settings.timeout,
            limits=httpx2.Limits(max_connections=4, max_keepalive_connections=0),
            transport=cn_transport(context, settings.server_cn),
        )

    @property
    def network(self) -> str:
        return self.settings.network

    async def close(self) -> None:
        await self.client.aclose()

    def _check_server(self, response: httpx2.Response) -> None:
        stream = response.extensions.get("network_stream")
        if stream is None:
            return
        ssl_object = stream.get_extra_info("ssl_object")
        if ssl_object is None:
            raise ValueError("node-owner TLS peer missing")
        if peer_cn(ssl_object.getpeercert()) != self.settings.server_cn:
            raise ValueError("unexpected node-owner server")

    async def _call(
        self,
        operation: str,
        *,
        node: str,
        generation: str,
        sandbox_id: str,
        pod_uid: str | None = None,
        volume_uid: str | None = None,
        inventory_sha256: str | None = None,
        boot_id: str | None = None,
        pod_uids: dict[str, str] | None = None,
        volumes: dict[str, dict[str, str]] | None = None,
        runtime_sha256: str | None = None,
        pv_uid: str | None = None,
    ) -> bytes:
        address = self.addresses.get(node)
        if not isinstance(address, str) or not address:
            raise ValueError("original node has no ready node-owner pod")
        endpoint = f"https://{address}:{self.port}"
        nonce = str(uuid4())
        body = msgspec.json.encode(
            {
                "schema": SCHEMA,
                "nonce": nonce,
                "operation": operation,
                "node": node,
                "namespace": self.settings.namespace,
                "network": self.network,
                "generation": generation,
                "sandbox_id": sandbox_id,
                "pod_uid": pod_uid,
                "volume_uid": volume_uid,
                "inventory_sha256": inventory_sha256,
                "boot_id": boot_id,
                **({"pv_uid": pv_uid} if operation.startswith("ipc-unused-") else {}),
                **({"pod_uids": pod_uids} if operation.startswith("partial-") else {}),
                **(
                    {"volumes": volumes, "runtime_sha256": runtime_sha256}
                    if operation.startswith("block-")
                    else {}
                ),
            }
        )
        async with asyncio.timeout(self.settings.timeout):
            async with self.client.stream(
                "POST",
                endpoint.rstrip("/") + "/v1/observe",
                content=body,
                headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
                extensions={"sni_hostname": self.settings.server_cn},
            ) as response:
                self._check_server(response)
                if (
                    response.status_code != 200
                    or response.headers.get("content-type") != "application/json"
                    or response.headers.get("content-encoding", "identity") != "identity"
                ):
                    raise RuntimeError("node-owner request rejected")
                raw = bytearray()
                async for part in response.aiter_raw():
                    raw.extend(part)
                    if len(raw) > LIMIT:
                        raise ValueError("node-owner response exceeds bound")
        result = json.loads(bytes(raw), object_pairs_hook=_unique)
        if (
            not isinstance(result, dict)
            or set(result) != {"schema", "nonce", "request_sha256", "report"}
            or result["schema"] != SCHEMA
            or result["nonce"] != nonce
            or result["request_sha256"] != hashlib.sha256(body).hexdigest()
            or not isinstance(result["report"], dict)
        ):
            raise ValueError("node-owner response correlation failed")
        report = msgspec.json.encode(result["report"])
        decoded: (
            IpcReleaseReport
            | NodeReleaseReport
            | PartialReleaseReport
            | IpcStorageReport
            | BlockReleaseReport
            | UnusedIpcStorageReport
        )
        if operation.startswith("block-"):
            decoded = decode_block_release(report)
        elif operation.startswith("ipc-unused-"):
            decoded = decode_unused_ipc_storage(report)
        elif operation.startswith("ipc-storage-"):
            decoded = decode_ipc_storage(report)
        elif operation.startswith("ipc-"):
            decoded = decode_ipc_release(report)
        elif operation.startswith("partial-"):
            decoded = decode_partial_release(report)
        else:
            decoded = decode_node_release(report)
        if (
            decoded.node != node
            or decoded.namespace != self.settings.namespace
            or str(decoded.generation) != generation
            or str(decoded.sandbox_id) != sandbox_id
            or (boot_id is not None and str(decoded.boot_id) != boot_id)
            or (inventory_sha256 is not None and decoded.inventory_sha256 != inventory_sha256)
            or (
                (
                    not decoded.observed
                    if isinstance(decoded, (IpcStorageReport, UnusedIpcStorageReport))
                    else decoded.leftovers is None
                )
                != operation.endswith("capture")
            )
        ):
            raise ValueError("node-owner returned a different original inventory")
        if isinstance(decoded, (NodeReleaseReport, PartialReleaseReport, BlockReleaseReport)):
            if decoded.network != self.network:
                raise ValueError("node-owner network mismatch")
            if (
                isinstance(decoded, PartialReleaseReport)
                and {key: str(uid) for key, uid in decoded.pod_uids.items()} != pod_uids
            ):
                raise ValueError("node-owner partial identity mismatch")
            if isinstance(decoded, BlockReleaseReport) and (
                decoded.runtime_sha256 != runtime_sha256
                or {
                    role: {
                        "name": v.name,
                        "volume_uid": str(v.volume_uid),
                        "pod_uid": str(v.pod_uid),
                    }
                    for role, v in decoded.volumes.items()
                }
                != volumes
            ):
                raise ValueError("node-owner original Block identity mismatch")
        elif isinstance(decoded, UnusedIpcStorageReport):
            if str(decoded.volume_uid) != volume_uid or str(decoded.pv_uid) != pv_uid:
                raise ValueError("node-owner unused IPC backing identity mismatch")
        elif str(decoded.pod_uid) != pod_uid or str(decoded.volume_uid) != volume_uid:
            raise ValueError("node-owner IPC identity mismatch")
        return report

    async def fence_and_capture(self, pair: PairBinding, *, node: str) -> bytes:
        return await self._call(
            "pair-capture",
            node=node,
            generation=str(pair.generation),
            sandbox_id=str(pair.sandbox_id),
        )

    async def observe(self, captured: NodeReleaseReport) -> bytes:
        raw = await self._call(
            "pair-observe",
            node=captured.node,
            generation=str(captured.generation),
            sandbox_id=str(captured.sandbox_id),
            boot_id=str(captured.boot_id),
            inventory_sha256=captured.inventory_sha256,
        )
        if set(decode_node_release(raw).pod_uids) != set(captured.pod_uids):
            raise ValueError("node-owner changed original private Pod identities")
        return raw

    async def capture_partial(
        self, pair: PairBinding, *, node: str, pod_uids: dict[str, str]
    ) -> bytes:
        return await self._call(
            "partial-capture",
            node=node,
            generation=str(pair.generation),
            sandbox_id=str(pair.sandbox_id),
            pod_uids=pod_uids,
        )

    async def observe_partial(self, captured: PartialReleaseReport) -> bytes:
        return await self._call(
            "partial-observe",
            node=captured.node,
            generation=str(captured.generation),
            sandbox_id=str(captured.sandbox_id),
            pod_uids={key: str(uid) for key, uid in captured.pod_uids.items()},
            boot_id=str(captured.boot_id),
            inventory_sha256=captured.inventory_sha256,
        )

    async def capture_ipc(
        self, pair: PairBinding, *, node: str, pod_uid: str, volume_uid: str
    ) -> bytes:
        return await self._call(
            "ipc-capture",
            node=node,
            generation=str(pair.generation),
            sandbox_id=str(pair.sandbox_id),
            pod_uid=pod_uid,
            volume_uid=volume_uid,
        )

    async def observe_ipc(self, captured: IpcReleaseReport) -> bytes:
        return await self._call(
            "ipc-observe",
            node=captured.node,
            generation=str(captured.generation),
            sandbox_id=str(captured.sandbox_id),
            pod_uid=str(captured.pod_uid),
            volume_uid=str(captured.volume_uid),
            boot_id=str(captured.boot_id),
            inventory_sha256=captured.inventory_sha256,
        )

    async def capture_ipc_storage(self, captured: IpcReleaseReport) -> bytes:
        raw = await self._call(
            "ipc-storage-capture",
            node=captured.node,
            generation=str(captured.generation),
            sandbox_id=str(captured.sandbox_id),
            pod_uid=str(captured.pod_uid),
            volume_uid=str(captured.volume_uid),
        )
        proof = decode_ipc_storage(raw)
        if proof.boot_id != captured.boot_id or proof.runtime_sha256 != captured.inventory_sha256:
            raise ValueError("storage capture differs from original IPC runtime")
        return raw

    async def capture_unused_ipc_storage(
        self, pair: PairBinding, *, node: str, volume_uid: str, pv_uid: str
    ) -> bytes:
        return await self._call(
            "ipc-unused-capture",
            node=node,
            generation=str(pair.generation),
            sandbox_id=str(pair.sandbox_id),
            volume_uid=volume_uid,
            pv_uid=pv_uid,
        )

    async def observe_unused_ipc_storage(self, captured: UnusedIpcStorageReport) -> bytes:
        return await self._call(
            "ipc-unused-observe",
            node=captured.node,
            generation=str(captured.generation),
            sandbox_id=str(captured.sandbox_id),
            volume_uid=str(captured.volume_uid),
            pv_uid=str(captured.pv_uid),
            boot_id=str(captured.boot_id),
            inventory_sha256=captured.inventory_sha256,
        )

    async def observe_ipc_storage(self, captured: IpcStorageReport) -> bytes:
        raw = await self._call(
            "ipc-storage-observe",
            node=captured.node,
            generation=str(captured.generation),
            sandbox_id=str(captured.sandbox_id),
            pod_uid=str(captured.pod_uid),
            volume_uid=str(captured.volume_uid),
            boot_id=str(captured.boot_id),
            inventory_sha256=captured.inventory_sha256,
        )
        proof = decode_ipc_storage(raw)
        if proof.pv_uid != captured.pv_uid or proof.runtime_sha256 != captured.runtime_sha256:
            raise ValueError("storage observation differs from original backing")
        return raw

    async def capture_block(
        self,
        captured: NodeReleaseReport | PartialReleaseReport,
        volumes: dict[str, dict[str, str]],
    ) -> bytes:
        raw = await self._call(
            "block-capture",
            node=captured.node,
            generation=str(captured.generation),
            sandbox_id=str(captured.sandbox_id),
            runtime_sha256=captured.inventory_sha256,
            volumes=volumes,
        )
        if decode_block_release(raw).boot_id != captured.boot_id:
            raise ValueError("Block capture boot differs from original runtime")
        return raw

    async def observe_block(self, captured: BlockReleaseReport) -> bytes:
        raw = await self._call(
            "block-observe",
            node=captured.node,
            generation=str(captured.generation),
            sandbox_id=str(captured.sandbox_id),
            runtime_sha256=captured.runtime_sha256,
            volumes={
                role: {"name": v.name, "volume_uid": str(v.volume_uid), "pod_uid": str(v.pod_uid)}
                for role, v in captured.volumes.items()
            },
            boot_id=str(captured.boot_id),
            inventory_sha256=captured.inventory_sha256,
        )
        if decode_block_release(raw).volumes != captured.volumes:
            raise ValueError("Block observation changed original backing identity")
        return raw
