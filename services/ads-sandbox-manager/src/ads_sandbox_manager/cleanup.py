from __future__ import annotations

from typing import Protocol

from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.objects import COMPONENT, Object
from ads_sandbox_manager.session_objects import CA_CONSUMER, SANDBOX, SESSION


class CleanupKubernetes(Protocol):
    async def inventory(self) -> list[Object]: ...
    async def observe(self, target: Object) -> Object | None: ...
    async def capture(self, target: Object) -> Object: ...
    async def delete(self, target: Object) -> None: ...
    async def observe_pod(self, name: str) -> Object | None: ...
    async def delete_pod(self, desired: Object, uid: str, *, node: str | None) -> bool: ...
    async def released(self, target: Object) -> bool: ...
    async def reclaimed(self, target: Object) -> bool: ...
    async def unreferenced(self, target: Object) -> bool: ...


class CleanupAdapter:
    """Exact deletes and positive release evidence. Never exec or mutate a Node/PV."""

    def __init__(self, kube: KubeClient) -> None:
        self.kube = kube

    async def inventory(self) -> list[Object]:
        k = self.kube
        objects = []
        for kind, method in (
            ("Deployment", k.apps.list_namespaced_deployment),
            ("PersistentVolumeClaim", k.core.list_namespaced_persistent_volume_claim),
        ):
            for obj in await k._list(method, k.settings.namespace):
                labels = obj.get("metadata", {}).get("labels", {})
                if labels.get(COMPONENT) in ("ads-sandbox", "ads-sandbox-ipc", CA_CONSUMER) and all(
                    labels.get(label) for label in (SANDBOX, SESSION)
                ):
                    obj["kind"] = kind
                    objects.append(obj)
        return objects

    async def observe(self, target: Object) -> Object | None:
        read = self.kube.deployment if target["kind"] == "Deployment" else self.kube.named_pvc
        return await read(target["name"])

    async def capture(self, target: Object) -> Object:
        """Persist stored bound-PV identity for a live claim before deletion.

        Deletion-time capture is the legacy compatibility path only: paired
        mint stores release evidence at creation/ready time, and this method
        records the same exact shape for sessions created before that change.
        Missing/replaced objects are not evidence and stay bare.
        """
        result = dict(target)
        if target["kind"] != "PersistentVolumeClaim":
            obj = await self.observe(target)
            if obj is not None and target["uid"] and obj["metadata"]["uid"] == target["uid"]:
                result["captured"] = True
            return result
        evidence = await self.kube.release_evidence(target["name"], target["uid"])
        if evidence is not None:
            result.update(evidence)
        return result

    @staticmethod
    def _uses(pod: Object, name: str) -> bool:
        return any(
            v.get("persistentVolumeClaim", {}).get("claimName") == name
            for v in pod.get("spec", {}).get("volumes", [])
        )

    async def delete(self, target: Object) -> None:
        obj = await self.observe(target)
        if obj is None or obj["metadata"]["uid"] != target["uid"]:
            return
        if obj["metadata"].get("deletionTimestamp"):
            return
        if target["kind"] == "PersistentVolumeClaim" and (
            obj.get("spec", {}).get("volumeName") != target.get("pv_name")
        ):
            raise RuntimeError("PVC binding changed after cleanup capture")
        k = self.kube
        method = (
            k.apps.delete_namespaced_deployment
            if target["kind"] == "Deployment"
            else k.core.delete_namespaced_persistent_volume_claim
        )
        try:
            await k._call(
                method,
                target["name"],
                k.settings.namespace,
                body={
                    "apiVersion": "v1",
                    "kind": "DeleteOptions",
                    "propagationPolicy": "Foreground",
                    "preconditions": {
                        "uid": target["uid"],
                        "resourceVersion": obj["metadata"]["resourceVersion"],
                    },
                },
            )
        except ApiException as exc:
            if exc.status not in (404, 409):
                raise

    async def observe_pod(self, name: str) -> Object | None:
        return await self.kube.named_pod(name)

    async def delete_pod(self, desired: Object, uid: str, *, node: str | None) -> bool:
        """Fenced Pod deletion: re-observe, then UID/RV preconditions.

        A never-scheduled Pod has no node; the deletion stays fenced by UID
        and resourceVersion alone, which is the same evidence the old
        unscheduled-pod proof relied on.
        """
        obj = await self.observe_pod(desired["metadata"]["name"])
        if obj is None or obj["metadata"]["uid"] != uid:
            raise RuntimeError("cleanup Pod was replaced")
        captured_node = obj.get("spec", {}).get("nodeName")
        if node is not None and captured_node != node:
            raise RuntimeError("cleanup Pod moved away from captured node")
        if node is None and captured_node is not None:
            raise RuntimeError("cleanup Pod was scheduled after unscheduled capture")
        k = self.kube
        try:
            await k._call(
                k.core.delete_namespaced_pod,
                obj["metadata"]["name"],
                k.settings.namespace,
                body={
                    "apiVersion": "v1",
                    "kind": "DeleteOptions",
                    "propagationPolicy": "Foreground",
                    "preconditions": {
                        "uid": obj["metadata"]["uid"],
                        "resourceVersion": obj["metadata"]["resourceVersion"],
                    },
                },
            )
        except ApiException as exc:
            if exc.status == 404:
                return True
            if exc.status == 409:
                return False
            raise
        return await self.observe_pod(obj["metadata"]["name"]) is None

    async def released(self, target: Object) -> bool:
        if not target.get("never_bound") and not (target.get("pv_name") and target.get("pv_uid")):
            return False
        return await self.unreferenced(target)

    async def unreferenced(self, target: Object) -> bool:
        """Conservative blockers only; an empty node list is never positive proof."""
        k = self.kube
        if not target.get("captured"):
            return False
        obj = await self.observe(target)
        if obj is not None and obj["metadata"]["uid"] != target["uid"]:
            raise RuntimeError("original storage claim was replaced")
        if obj is not None and obj.get("spec", {}).get("volumeName") != target.get("pv_name"):
            return False
        pods = await k._list(k.core.list_namespaced_pod, k.settings.namespace)
        if any(self._uses(pod, target["name"]) for pod in pods):
            return False  # Terminal/deleting Pods are still unfinished runtime evidence.
        if target.get("never_bound"):
            return True
        if not target.get("pv_name"):
            return False
        attachments = await k._list(k.storage.list_volume_attachment)
        if any(
            a.get("spec", {}).get("source", {}).get("persistentVolumeName") == target["pv_name"]
            for a in attachments
        ):
            return False
        return True

    async def _storage_class_contract(self, name: str) -> Object:
        value = await self.kube._call(self.kube.storage.read_storage_class, name)
        return {
            "name": value["metadata"]["name"],
            "uid": value["metadata"]["uid"],
            "created": value["metadata"]["creationTimestamp"],
            "provisioner": value["provisioner"],
            "binding": value.get("volumeBindingMode", "Immediate"),
        }

    async def reclaimed(self, target: Object) -> bool:
        obj = await self.observe(target)
        if obj is not None and obj["metadata"]["uid"] == target["uid"]:
            return False
        if not await self.released(target):
            return False
        if target.get("never_bound"):
            return True
        try:
            await self.kube._call(self.kube.core.read_persistent_volume, target["pv_name"])
        except ApiException as exc:
            if exc.status == 404:
                return True
            raise
        # A replacement PV is not proof that the old backing store was reclaimed;
        # its reclamation is the storage driver's contract, not stored evidence.
        return False
