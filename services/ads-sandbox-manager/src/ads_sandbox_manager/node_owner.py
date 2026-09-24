"""Authenticated, bounded delivery to explicitly configured node owners."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx2
import msgspec

from ads_commons.sandbox.ipc_release import IpcReleaseReport, decode_ipc_release
from ads_commons.sandbox.node_release import NodeReleaseReport, _unique, decode_node_release
from ads_sandbox_manager.pair_objects import PairBinding

LIMIT = 32768
SCHEMA = "ads-node-owner-v1"


@dataclass(frozen=True)
class NodeOwnerSettings:
    endpoints: dict[str, str]
    namespace: str
    network: str
    ca: Path
    certificate: Path
    key: Path = field(repr=False)
    timeout: float = 60

    def __post_init__(self) -> None:
        if (
            not self.endpoints
            or not self.namespace.strip()
            or not self.network.strip()
            or not math.isfinite(self.timeout)
            or not 0 < self.timeout <= 70
        ):
            raise ValueError("bounded explicit node-owner configuration required")
        for node, endpoint in self.endpoints.items():
            parsed = urlsplit(endpoint)
            if (
                not node.strip()
                or parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
                or parsed.port == 0
            ):
                raise ValueError("credential-free node HTTPS origin required")
        if len(set(self.endpoints.values())) != len(self.endpoints):
            raise ValueError("each node requires its own explicit endpoint")
        if not all(path.is_absolute() for path in (self.ca, self.certificate, self.key)):
            raise ValueError("absolute node TLS credential paths required")

    @classmethod
    def parse(cls, value: dict[str, Any]) -> NodeOwnerSettings:
        if not isinstance(value, dict) or set(value) != {
            "endpoints",
            "namespace",
            "network",
            "ca",
            "certificate",
            "key",
            "timeout",
        }:
            raise ValueError("exact node-owner configuration required")
        if (
            not isinstance(value["endpoints"], dict)
            or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in value["endpoints"].items()
            )
            or not all(
                isinstance(value[k], str)
                for k in ("namespace", "network", "ca", "certificate", "key")
            )
            or type(value["timeout"]) not in (int, float)
        ):
            raise ValueError("invalid node-owner configuration types")
        return cls(
            endpoints=dict(value["endpoints"]),
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
        context.load_cert_chain(str(self.certificate), str(self.key))
        return context


class HttpsNodeOwner:
    def __init__(self, settings: NodeOwnerSettings, context: ssl.SSLContext) -> None:
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("verified mutual TLS required")
        self.settings = settings
        self.client = httpx2.AsyncClient(
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=settings.timeout,
            limits=httpx2.Limits(max_connections=4, max_keepalive_connections=0),
        )

    @property
    def network(self) -> str:
        return self.settings.network

    async def close(self) -> None:
        await self.client.aclose()

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
    ) -> bytes:
        endpoint = self.settings.endpoints.get(node)
        if endpoint is None:
            raise ValueError("original node has no configured trusted endpoint")
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
            }
        )
        async with asyncio.timeout(self.settings.timeout):
            async with self.client.stream(
                "POST",
                endpoint.rstrip("/") + "/v1/observe",
                content=body,
                headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
            ) as response:
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
        decoded = (
            decode_ipc_release(report)
            if operation.startswith("ipc-")
            else decode_node_release(report)
        )
        if (
            decoded.node != node
            or decoded.namespace != self.settings.namespace
            or str(decoded.generation) != generation
            or str(decoded.sandbox_id) != sandbox_id
            or (boot_id is not None and str(decoded.boot_id) != boot_id)
            or (inventory_sha256 is not None and decoded.inventory_sha256 != inventory_sha256)
            or (decoded.leftovers is None) != operation.endswith("capture")
        ):
            raise ValueError("node-owner returned a different original inventory")
        if isinstance(decoded, NodeReleaseReport):
            if decoded.network != self.network:
                raise ValueError("node-owner network mismatch")
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
