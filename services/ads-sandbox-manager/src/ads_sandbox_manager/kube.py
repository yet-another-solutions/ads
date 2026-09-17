from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import Object


class Kubernetes(Protocol):
    async def job(self) -> Object | None: ...
    async def pvc(self) -> Object | None: ...
    async def create_job(self, body: Object) -> None: ...
    async def create_pvc(self, body: Object) -> None: ...
    async def delete_job(self, observed: Object) -> None: ...
    async def delete_pvc(self, observed: Object) -> None: ...
    async def released(self, pvc: Object, job: Object | None) -> bool: ...


def timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else None


class KubeClient:
    """In-cluster, verified TLS only. No exec, kubeconfig, node writes, or RBAC writes."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        configuration = client.Configuration()
        config.load_incluster_config(client_configuration=configuration)
        if not configuration.host.startswith("https://") or not configuration.verify_ssl:
            raise ValueError("Kubernetes requires verified HTTPS")
        configuration.retries = 0  # Polling owns retries; do not retry stale writes in urllib3.
        self.api_client = client.ApiClient(configuration)
        self.core = client.CoreV1Api(self.api_client)
        self.batch = client.BatchV1Api(self.api_client)
        self.storage = client.StorageV1Api(self.api_client)

    async def close(self) -> None:
        await asyncio.to_thread(self.api_client.close)

    async def _call(self, method: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        result = await asyncio.to_thread(
            method, *args, **kwargs, _request_timeout=self.settings.control_seconds
        )
        return self.api_client.sanitize_for_serialization(result)

    async def _get(self, method: Callable[..., Any]) -> Object | None:
        try:
            return cast(
                Object, await self._call(method, self.settings.golden_name, self.settings.namespace)
            )
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    async def job(self) -> Object | None:
        return await self._get(self.batch.read_namespaced_job)

    async def pvc(self) -> Object | None:
        return await self._get(self.core.read_namespaced_persistent_volume_claim)

    async def create_job(self, body: Object) -> None:
        await self._call(self.batch.create_namespaced_job, self.settings.namespace, body)

    async def create_pvc(self, body: Object) -> None:
        await self._call(
            self.core.create_namespaced_persistent_volume_claim, self.settings.namespace, body
        )

    async def _delete(self, method: Callable[..., Any], observed: Object) -> None:
        meta = observed["metadata"]
        # Both preconditions matter: a stale replica may not delete a replacement or a
        # Job whose status changed after it was read.
        body = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": meta["uid"], "resourceVersion": meta["resourceVersion"]},
            "propagationPolicy": "Foreground",
        }
        await self._call(method, self.settings.golden_name, self.settings.namespace, body=body)

    async def delete_job(self, observed: Object) -> None:
        await self._delete(self.batch.delete_namespaced_job, observed)

    async def delete_pvc(self, observed: Object) -> None:
        await self._delete(self.core.delete_namespaced_persistent_volume_claim, observed)

    async def _list(self, method: Callable[..., Any], *args: Any) -> list[Object]:
        items: list[Object] = []
        continuation = ""
        while True:
            page = await self._call(method, *args, limit=200, _continue=continuation)
            items.extend(page["items"])
            continuation = page.get("metadata", {}).get("continue", "")
            if not continuation:
                return items

    async def released(self, pvc: Object, job: Object | None) -> bool:
        """Positive API evidence, not PVC phase != Bound or absence of attachments alone."""
        name = self.settings.golden_name
        pods = await self._list(self.core.list_namespaced_pod, self.settings.namespace)
        consumers = [
            pod
            for pod in pods
            if any(
                v.get("persistentVolumeClaim", {}).get("claimName") == name
                for v in pod.get("spec", {}).get("volumes", [])
            )
        ]
        nodes: dict[str, datetime] = {}
        owned = False
        for pod in consumers:
            status = pod.get("status", {})
            meta = pod["metadata"]
            # Terminating is not released. Unknown/missing phase is not terminal.
            if meta.get("deletionTimestamp") or status.get("phase") not in ("Succeeded", "Failed"):
                return False
            # A terminal container alone doesn't prove that the Kata VM has gone.
            if not any(
                c.get("type") == "PodReadyToStartContainers" and c.get("status") == "False"
                for c in status.get("conditions", [])
            ):
                return False
            ended = [
                timestamp(c.get("state", {}).get("terminated", {}).get("finishedAt"))
                for c in status.get("containerStatuses", [])
            ]
            node = pod.get("spec", {}).get("nodeName")
            if not node or not ended or any(t is None for t in ended):
                return False
            finished = max(t for t in ended if t is not None)
            nodes[node] = max(nodes.get(node, finished), finished)
            if (
                job is not None
                and any(
                    r.get("uid") == job["metadata"]["uid"]
                    and r.get("controller") is True
                    and r.get("kind") == "Job"
                    for r in meta.get("ownerReferences", [])
                )
                and status["phase"] == "Succeeded"
            ):
                owned = True
        # Retain the completed Job and its Pod as bake/node evidence. If an operator
        # removes it, do not infer release from an empty list after a restart.
        if job is not None and not owned:
            return False
        pv_name = pvc.get("spec", {}).get("volumeName")
        if not pv_name:
            return job is None and not consumers and pvc.get("status", {}).get("phase") == "Pending"
        if not nodes:
            # A Bound orphan without any retained consumer/node evidence is ambiguous,
            # especially for CSI drivers that do not create VolumeAttachments.
            return False
        pv = await self._call(self.core.read_persistent_volume, pv_name)
        claim = pv.get("spec", {}).get("claimRef", {})
        csi = pv.get("spec", {}).get("csi", {})
        if (
            claim.get("uid") != pvc["metadata"]["uid"]
            or claim.get("name") != name
            or claim.get("namespace") != self.settings.namespace
            or not csi.get("driver")
            or not csi.get("volumeHandle")
        ):
            return False
        unique = f"kubernetes.io/csi/{csi['driver']}^{csi['volumeHandle']}"
        now = datetime.now(UTC)
        for node_name, finished in nodes.items():
            node = await self._call(self.core.read_node, node_name)
            status = node.get("status", {})
            ready: Object = next(
                (c for c in status.get("conditions", []) if c.get("type") == "Ready"), {}
            )
            heartbeat = timestamp(ready.get("lastHeartbeatTime"))
            if (
                ready.get("status") != "True"
                or heartbeat is None
                or heartbeat < finished
                or not 0 <= (now - heartbeat).total_seconds() <= self.settings.node_fresh_seconds
            ):
                return False
            if unique in status.get("volumesInUse", []) or any(
                v.get("name") == unique for v in status.get("volumesAttached", [])
            ):
                return False
        attachments = await self._list(self.storage.list_volume_attachment)
        # Even attached=False/deleting/error objects are unfinished observations.
        return not any(
            a.get("spec", {}).get("source", {}).get("persistentVolumeName") == pv_name
            for a in attachments
        )
