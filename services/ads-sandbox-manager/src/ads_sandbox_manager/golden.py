from __future__ import annotations

from kubernetes.utils.quantity import parse_quantity

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.kube import Kubernetes
from ads_sandbox_manager.objects import (
    COMPONENT,
    JOB_UID,
    VERSION,
    Object,
    golden_job,
    golden_pvc,
)


def condition(job: Object, name: str) -> bool:
    return any(
        c.get("type") == name and c.get("status") == "True"
        for c in job.get("status", {}).get("conditions", [])
    )


class GoldenEnsure:
    """System lifecycle, not a callable user/business API. Durable state is in Kubernetes."""

    def __init__(self, settings: Settings, kube: Kubernetes) -> None:
        self.settings = settings
        self.kube = kube

    def _owned(self, obj: Object) -> bool:
        meta = obj.get("metadata", {})
        labels = meta.get("labels", {})
        return (
            meta.get("name") == self.settings.golden_name
            and meta.get("namespace") == self.settings.namespace
            and bool(meta.get("uid"))
            and bool(meta.get("resourceVersion"))
            and labels.get(VERSION) == self.settings.golden_version
            and labels.get(COMPONENT) == "ads-sandbox-golden"
        )

    def _valid_pvc(self, pvc: Object) -> bool:
        spec = pvc.get("spec", {})
        return (
            self._owned(pvc)
            and spec.get("storageClassName") == "sandbox-block"
            and spec.get("volumeMode") == "Block"
            and spec.get("accessModes") == ["ReadWriteOnce"]
            and not spec.get("dataSource")
            and not spec.get("dataSourceRef")
            and parse_quantity(spec.get("resources", {}).get("requests", {}).get("storage", "0"))
            == self.settings.golden_bytes
        )

    async def poll(self) -> bool:
        return await self.clone_source() is not None

    async def clone_source(self) -> Object | None:
        """Return the exact fenced PVC observation, not a later same-name replacement."""
        job, pvc = await self.kube.job(), await self.kube.pvc()
        if job is not None and not self._owned(job):
            raise RuntimeError("foreign golden Job; refusing adoption or deletion")
        if pvc is not None and not self._valid_pvc(pvc):
            raise RuntimeError("foreign or incompatible golden PVC; refusing adoption or deletion")
        if any(o is not None and o["metadata"].get("deletionTimestamp") for o in (job, pvc)):
            return None
        if (
            job is not None
            and pvc is not None
            and (pvc["metadata"]["labels"].get(JOB_UID) != job["metadata"]["uid"])
        ):
            raise RuntimeError("golden PVC belongs to a different bake attempt")
        if job is None:
            if pvc is not None:
                # A partial orphan is never promoted to ready. Delete before acquiring
                # the new Job lock, with UID/RV fencing against another replica.
                if await self.kube.released(pvc, None):
                    await self.kube.delete_pvc(pvc)
            else:
                # Acquire the Kubernetes name lock BEFORE creating the claim.
                await self.kube.create_job(golden_job(self.settings))
            return None
        failed, complete = condition(job, "Failed"), condition(job, "Complete")
        if failed or (complete and pvc is None):
            # Keep the old Job name locked until its partial disk has disappeared.
            if pvc is not None:
                if await self.kube.released(pvc, None):
                    await self.kube.delete_pvc(pvc)
            else:
                await self.kube.delete_job(job)
            return None
        if pvc is None:
            # Pending/unscheduled is in progress, not a failed bake. Any replica can
            # repair a winner's crash between Job creation and PVC creation.
            await self.kube.create_pvc(golden_pvc(self.settings, job["metadata"]["uid"]))
            return None
        if (
            not complete
            or job.get("status", {}).get("active", 0)
            or job.get("status", {}).get("terminating", 0)
        ):
            return None
        if pvc.get("status", {}).get("phase") != "Bound":
            return None
        if not await self.kube.released(pvc, job):
            return None
        # Fence the multi-resource observation against replacements during release checks.
        current_job, current_pvc = await self.kube.job(), await self.kube.pvc()
        unchanged = all(
            current is not None
            and current["metadata"]["uid"] == old["metadata"]["uid"]
            and current["metadata"]["resourceVersion"] == old["metadata"]["resourceVersion"]
            and not current["metadata"].get("deletionTimestamp")
            for current, old in ((current_job, job), (current_pvc, pvc))
        )
        return pvc if unchanged else None
