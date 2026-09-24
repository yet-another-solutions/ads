from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
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
    async def released(self, target: Object) -> bool: ...
    async def reclaimed(self, target: Object) -> bool: ...
    async def unreferenced(self, target: Object) -> bool: ...
    async def capture_unused(self, target: Object, *, unissued: bool) -> Object: ...
    async def dispose_unused(self, captured: Object) -> bool: ...


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
        """Persist before deletion, including bound PV UID and nodes seen using the claim."""
        result = dict(target)
        obj = await self.observe(target)
        if obj is None or not target["uid"] or obj["metadata"]["uid"] != target["uid"]:
            return result  # Missing/replaced is not evidence of release/reclamation.
        result["captured"] = True
        if target["kind"] != "PersistentVolumeClaim":
            return result
        k = self.kube
        pods = await k._list(k.core.list_namespaced_pod, k.settings.namespace)
        result["nodes"] = sorted(
            {
                pod["spec"]["nodeName"]
                for pod in pods
                if pod.get("spec", {}).get("nodeName") and self._uses(pod, target["name"])
            }
        )
        result["observed_at"] = datetime.now(UTC).isoformat()
        pv_name = obj.get("spec", {}).get("volumeName")
        if not pv_name:
            result["never_bound"] = obj.get("status", {}).get("phase") == "Pending"
            return result
        pv = await k._call(k.core.read_persistent_volume, pv_name)
        spec = pv.get("spec", {})
        claim = spec.get("claimRef", {})
        if (
            claim.get("uid") != target["uid"]
            or claim.get("name") != target["name"]
            or claim.get("namespace") != k.settings.namespace
        ):
            raise RuntimeError("PV claim identity changed")
        result["pv_name"], result["pv_uid"] = pv_name, pv["metadata"]["uid"]
        result["delete_policy"] = spec.get("persistentVolumeReclaimPolicy") == "Delete"
        csi = spec.get("csi", {})
        result["volume_key"] = (
            f"kubernetes.io/csi/{csi['driver']}^{csi['volumeHandle']}"
            if csi.get("driver") and csi.get("volumeHandle")
            else None
        )
        # CSI deletion protection is the controller's storage-reclamation contract.
        result["reclaim_guard"] = "external-provisioner.volume.kubernetes.io/finalizer" in pv.get(
            "metadata", {}
        ).get("finalizers", [])
        if not csi and obj.get("spec", {}).get("volumeMode", "Filesystem") == "Filesystem":
            sources = [kind for kind in ("local", "hostPath") if kind in spec]
            if len(sources) == 1:
                source = sources[0]
                result["filesystem_backing"] = {
                    "source": source,
                    "path": deepcopy(spec[source].get("path")),
                }
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

    async def released(self, target: Object) -> bool:
        if not target.get("never_bound") and not (target.get("pv_name") and target.get("nodes")):
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
        for name in target["nodes"]:
            node = await k._call(k.core.read_node, name)
            status = node.get("status", {})
            # Node health/heartbeat is not workload or volume-release evidence.
            # Keep volume-specific negative observations as conservative blockers.
            key = target.get("volume_key")
            if key and (
                key in status.get("volumesInUse", [])
                or any(v.get("name") == key for v in status.get("volumesAttached", []))
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

    async def capture_unused(self, target: Object, *, unissued: bool) -> Object:
        evidence = await self.capture(target)
        if not evidence.get("captured") or evidence.get("nodes"):
            raise RuntimeError("original unused storage capture unavailable")
        result = {
            "mode": "never-mounted-csi",
            "target": evidence,
            "storage_class": None,
            "pvc_created": None,
        }
        if not evidence.get("never_bound"):
            return result  # Repository checks the positive consumer and CSI contract.
        obj = await self.observe(target)
        if (
            not unissued
            or obj is None
            or obj["metadata"]["uid"] != target["uid"]
            or obj.get("spec", {}).get("volumeName")
            or obj["metadata"].get("annotations", {}).get("volume.kubernetes.io/selected-node")
            or obj.get("status", {}).get("phase") != "Pending"
        ):
            raise RuntimeError("unbound provisioning history is ambiguous")
        result.update(
            mode="never-provisioned",
            storage_class=await self._storage_class_contract(obj["spec"]["storageClassName"]),
            pvc_created=obj["metadata"]["creationTimestamp"],
        )
        return result

    async def dispose_unused(self, captured: Object) -> bool:
        target = captured["target"]
        if not await self.unreferenced(target):
            return False
        obj = await self.observe(target)
        if obj is not None:
            if obj["metadata"]["uid"] != target["uid"]:
                raise RuntimeError("unused claim replacement refuses disposition")
            if captured["mode"] == "never-provisioned":
                if (
                    target["retain"]
                    or obj.get("spec", {}).get("volumeName")
                    or obj.get("status", {}).get("phase") != "Pending"
                    or obj["metadata"]
                    .get("annotations", {})
                    .get("volume.kubernetes.io/selected-node")
                    or obj["metadata"].get("creationTimestamp") != captured["pvc_created"]
                    or await self._storage_class_contract(obj["spec"]["storageClassName"])
                    != captured["storage_class"]
                ):
                    raise RuntimeError("original never-provisioned contract changed")
                # The RV precondition binds the unbound/unselected observation;
                # do not re-read a changed claim then silently use its new RV.
                try:
                    await self.kube._call(
                        self.kube.core.delete_namespaced_persistent_volume_claim,
                        target["name"],
                        self.kube.settings.namespace,
                        body={
                            "apiVersion": "v1",
                            "kind": "DeleteOptions",
                            "preconditions": {
                                "uid": target["uid"],
                                "resourceVersion": obj["metadata"]["resourceVersion"],
                            },
                        },
                    )
                except ApiException as exc:
                    if exc.status == 409:
                        return False
                    if exc.status != 404:
                        raise
            else:
                current = await self.capture(target)
                if any(
                    current.get(key) != target[key]
                    for key in ("pv_name", "pv_uid", "volume_key", "delete_policy", "reclaim_guard")
                ):
                    raise RuntimeError("unused original CSI backing changed")
                if target["retain"]:
                    if obj["metadata"].get("deletionTimestamp"):
                        raise RuntimeError("retained unused claim is terminating")
                    return True
                await self.delete(target)
        elif target["retain"]:
            raise RuntimeError("retained unused claim disappeared")
        if await self.observe(target) is not None or not await self.unreferenced(target):
            return False
        if captured["mode"] == "never-provisioned":
            return True  # Original positive ledger/contract, not API absence alone.
        if not (target["delete_policy"] and target["reclaim_guard"]):
            return False
        try:
            await self.kube._call(self.kube.core.read_persistent_volume, target["pv_name"])
        except ApiException as exc:
            if exc.status == 404:
                return True
            raise
        return False

    async def reclaimed(self, target: Object) -> bool:
        obj = await self.observe(target)
        if obj is not None and obj["metadata"]["uid"] == target["uid"]:
            return False
        if not await self.released(target):
            return False
        if target.get("never_bound"):
            return True
        if not target.get("delete_policy") or not target.get("reclaim_guard"):
            return False
        try:
            await self.kube._call(self.kube.core.read_persistent_volume, target["pv_name"])
        except ApiException as exc:
            if exc.status == 404:
                return True
            raise
        # A replacement PV is not proof that the old backing store was reclaimed.
        return False
