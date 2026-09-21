from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol, cast

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.ca_objects import CA_NAME, CA_ROLES
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import JOB_UID, Object


class Kubernetes(Protocol):
    async def job(self) -> Object | None: ...
    async def pvc(self) -> Object | None: ...
    async def create_job(self, body: Object) -> None: ...
    async def create_pvc(self, body: Object) -> None: ...
    async def delete_job(self, observed: Object) -> None: ...
    async def delete_pvc(self, observed: Object) -> None: ...
    async def delete_released_bake_pods(self, pvc: Object, job: Object) -> None: ...
    async def released(self, pvc: Object, job: Object | None) -> bool: ...
    async def named_job(self, name: str) -> Object | None: ...
    async def named_pvc(self, name: str) -> Object | None: ...
    async def delete_released_ca_pods(self, job: Object, claims: list[Object]) -> None: ...


class SessionKubernetes(Protocol):
    async def named_pvc(self, name: str) -> Object | None: ...
    async def deployment(self, name: str) -> Object | None: ...
    async def create_pvc(self, body: Object) -> None: ...
    async def create_deployment(self, body: Object) -> None: ...


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
        self.apps = client.AppsV1Api(self.api_client)

    async def close(self) -> None:
        await asyncio.to_thread(self.api_client.close)

    async def _call(self, method: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        result = await asyncio.to_thread(
            method, *args, **kwargs, _request_timeout=self.settings.control_seconds
        )
        return self.api_client.sanitize_for_serialization(result)

    async def _get(self, method: Callable[..., Any], name: str | None = None) -> Object | None:
        try:
            return cast(
                Object,
                await self._call(
                    method,
                    name or self.settings.golden_name,
                    self.settings.namespace,
                ),
            )
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    async def job(self) -> Object | None:
        return await self._get(self.batch.read_namespaced_job)

    async def named_job(self, name: str) -> Object | None:
        return await self._get(self.batch.read_namespaced_job, name)

    async def pvc(self) -> Object | None:
        return await self._get(self.core.read_namespaced_persistent_volume_claim)

    async def named_pvc(self, name: str) -> Object | None:
        return await self._get(self.core.read_namespaced_persistent_volume_claim, name)

    async def deployment(self, name: str) -> Object | None:
        return await self._get(self.apps.read_namespaced_deployment, name)

    async def create_deployment(self, body: Object) -> None:
        await self._call(self.apps.create_namespaced_deployment, self.settings.namespace, body)

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
        await self._call(method, meta["name"], self.settings.namespace, body=body)

    async def delete_job(self, observed: Object) -> None:
        await self._delete(self.batch.delete_namespaced_job, observed)

    async def delete_pvc(self, observed: Object) -> None:
        await self._delete(self.core.delete_namespaced_persistent_volume_claim, observed)

    async def delete_released_bake_pods(self, pvc: Object, job: Object) -> None:
        """Remove only failed-attempt evidence after disk release, retaining the Job lock."""
        current_job, current_pvc = await self.job(), await self.pvc()
        if (
            current_job is None
            or current_pvc is None
            or current_job["metadata"].get("deletionTimestamp")
            or not current_pvc["metadata"].get("deletionTimestamp")
            or current_job["metadata"].get("uid") != job["metadata"]["uid"]
            or current_job["metadata"].get("resourceVersion") != job["metadata"]["resourceVersion"]
            or current_pvc["metadata"].get("uid") != pvc["metadata"]["uid"]
            or current_pvc["metadata"].get("labels", {}).get(JOB_UID) != job["metadata"]["uid"]
            or not any(
                c.get("type") == "Failed" and c.get("status") == "True"
                for c in current_job.get("status", {}).get("conditions", [])
            )
        ):
            return
        pods = await self._list(self.core.list_namespaced_pod, self.settings.namespace)
        if not await self.released(current_pvc, None):
            return
        for pod in pods:
            meta = pod.get("metadata", {})
            if (
                meta.get("uid")
                and meta.get("resourceVersion")
                and not meta.get("deletionTimestamp")
                and pod.get("status", {}).get("phase") in ("Succeeded", "Failed")
                and any(
                    ref.get("kind") == "Job"
                    and ref.get("controller") is True
                    and ref.get("uid") == job["metadata"]["uid"]
                    for ref in meta.get("ownerReferences", [])
                )
                and any(
                    v.get("persistentVolumeClaim", {}).get("claimName") == self.settings.golden_name
                    for v in pod.get("spec", {}).get("volumes", [])
                )
            ):
                await self._delete(self.core.delete_namespaced_pod, pod)

    async def _list(self, method: Callable[..., Any], *args: Any) -> list[Object]:
        items: list[Object] = []
        continuation = ""
        while True:
            page = await self._call(method, *args, limit=200, _continue=continuation)
            items.extend(page["items"])
            continuation = page.get("metadata", {}).get("continue", "")
            if not continuation:
                return items

    async def delete_released_ca_pods(self, job: Object, claims: list[Object]) -> None:
        """Keep the Job lock; remove terminal Pod evidence only after paired deletion/release."""
        current_job = await self.named_job(CA_NAME)
        if (
            current_job is None
            or current_job["metadata"].get("deletionTimestamp")
            or any(
                current_job["metadata"].get(key) != job["metadata"][key]
                for key in ("uid", "resourceVersion")
            )
            or not any(
                c.get("type") in ("Failed", "Complete") and c.get("status") == "True"
                for c in current_job.get("status", {}).get("conditions", [])
            )
        ):
            return
        observed = {pvc["metadata"]["name"]: pvc for pvc in claims}
        names = {f"{CA_NAME}-{role}" for role in CA_ROLES}
        for name in names:
            current = await self.named_pvc(name)
            if current is None:
                continue
            old = observed.get(name)
            if (
                old is None
                or current["metadata"].get("uid") != old["metadata"]["uid"]
                or current["metadata"].get("labels", {}).get(JOB_UID) != job["metadata"]["uid"]
                or not current["metadata"].get("deletionTimestamp")
                or not await self.released(current, None)
            ):
                return
        pods = await self._list(self.core.list_namespaced_pod, self.settings.namespace)
        for pod in pods:
            meta = pod.get("metadata", {})
            if (
                meta.get("uid")
                and meta.get("resourceVersion")
                and not meta.get("deletionTimestamp")
                and pod.get("status", {}).get("phase") in ("Succeeded", "Failed")
                and any(
                    ref.get("kind") == "Job"
                    and ref.get("controller") is True
                    and ref.get("uid") == job["metadata"]["uid"]
                    for ref in meta.get("ownerReferences", [])
                )
                and any(
                    v.get("persistentVolumeClaim", {}).get("claimName") in names
                    for v in pod.get("spec", {}).get("volumes", [])
                )
            ):
                await self._delete(self.core.delete_namespaced_pod, pod)

    async def released(self, pvc: Object, job: Object | None) -> bool:
        """Positive API evidence, not PVC phase != Bound or absence of attachments alone."""
        name = pvc["metadata"]["name"]
        pods = await self._list(self.core.list_namespaced_pod, self.settings.namespace)
        consumers = [
            pod
            for pod in pods
            if any(
                v.get("persistentVolumeClaim", {}).get("claimName") == name
                for v in pod.get("spec", {}).get("volumes", [])
            )
        ]
        pv_name = pvc.get("spec", {}).get("volumeName")
        if not pv_name:
            # A never-bound claim cannot have been published to a Pod. Permit failed
            # pre-scheduling cleanup without inventing node/VM evidence. UID/RV
            # delete preconditions fence a concurrent bind; live Pods still block.
            return (
                job is None
                and pvc.get("status", {}).get("phase") == "Pending"
                and all(
                    not pod.get("metadata", {}).get("deletionTimestamp")
                    and pod.get("status", {}).get("phase") in ("Succeeded", "Failed")
                    for pod in consumers
                )
            )
        nodes: set[str] = set()
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
            nodes.add(node)
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
        for node_name in nodes:
            node = await self._call(self.core.read_node, node_name)
            status = node.get("status", {})
            # Node Ready and heartbeat freshness are not storage-release signals.
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
