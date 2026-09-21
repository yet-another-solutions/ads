from __future__ import annotations

from typing import Protocol

from kubernetes.utils.quantity import parse_quantity

from ads_sandbox_manager.ca_objects import (
    CA_FORMAT,
    CA_NAME,
    CA_ROLE,
    CA_ROLES,
    ca_job,
    ca_pvc,
)
from ads_sandbox_manager.config import Settings, size_bytes
from ads_sandbox_manager.golden import condition
from ads_sandbox_manager.objects import COMPONENT, JOB_UID, Object


class CaKubernetes(Protocol):
    async def named_job(self, name: str) -> Object | None: ...
    async def named_pvc(self, name: str) -> Object | None: ...
    async def create_job(self, body: Object) -> None: ...
    async def create_pvc(self, body: Object) -> None: ...
    async def delete_job(self, observed: Object) -> None: ...
    async def delete_pvc(self, observed: Object) -> None: ...
    async def released(self, pvc: Object, job: Object | None) -> bool: ...
    async def delete_released_ca_pods(self, job: Object, claims: list[Object]) -> None: ...


def same_observation(current: Object | None, old: Object) -> bool:
    return (
        current is not None
        and all(
            current["metadata"].get(k) == old["metadata"][k] for k in ("uid", "resourceVersion")
        )
        and not current["metadata"].get("deletionTimestamp")
    )


class CaEnsure:
    """The golden Job-first protocol applied to one indivisible pair of CA outputs."""

    def __init__(self, settings: Settings, kube: CaKubernetes) -> None:
        if settings.ca is None:
            raise ValueError("CA inputs are required")
        self.settings, self.kube, self.ca = settings, kube, settings.ca

    def _owned(self, obj: Object, role: str | None) -> bool:
        meta = obj.get("metadata", {})
        labels = meta.get("labels", {})
        return (
            meta.get("name") == (CA_NAME if role is None else f"{CA_NAME}-{role}")
            and meta.get("namespace") == self.settings.namespace
            and bool(meta.get("uid"))
            and bool(meta.get("resourceVersion"))
            and labels.get(COMPONENT) == CA_NAME
            and labels.get(CA_FORMAT) == "1"
            and (role is None or labels.get(CA_ROLE) == role)
        )

    def _valid_pvc(self, pvc: Object, role: str) -> bool:
        spec = pvc.get("spec", {})
        return (
            self._owned(pvc, role)
            and spec.get("storageClassName") == "sandbox-block"
            and spec.get("volumeMode") == "Block"
            and spec.get("accessModes") == ["ReadWriteOnce"]
            and not spec.get("dataSource")
            and not spec.get("dataSourceRef")
            and parse_quantity(spec.get("resources", {}).get("requests", {}).get("storage", "0"))
            == size_bytes(self.ca.source_size)
        )

    async def _observe(self) -> tuple[Object | None, dict[str, Object | None]]:
        job = await self.kube.named_job(CA_NAME)
        claims = {role: await self.kube.named_pvc(f"{CA_NAME}-{role}") for role in CA_ROLES}
        if job is not None and not self._owned(job, None):
            raise RuntimeError("foreign CA Job; refusing adoption or deletion")
        for role, pvc in claims.items():
            if pvc is not None:
                if not self._valid_pvc(pvc, role):
                    raise RuntimeError("foreign or incompatible CA output; refusing deletion")
                if (
                    job is not None
                    and pvc["metadata"]["labels"].get(JOB_UID) != job["metadata"]["uid"]
                ):
                    raise RuntimeError("CA output belongs to a different initialization attempt")
        return job, claims

    async def poll(self) -> bool:
        return await self.clone_sources() is not None

    async def clone_sources(self) -> dict[str, Object] | None:
        job, claims = await self._observe()
        existing = [pvc for pvc in claims.values() if pvc is not None]
        if job is not None and job["metadata"].get("deletionTimestamp"):
            return None
        complete = job is not None and condition(job, "Complete")
        failed = job is not None and condition(job, "Failed")
        deleting = any(pvc["metadata"].get("deletionTimestamp") for pvc in existing)
        if job is None or failed or complete and (len(existing) != 2 or deleting):
            # A single missing/deleting output invalidates the whole pair. Keep the
            # retained Job name locked until BOTH old claims have disappeared.
            if existing:
                if not all([await self.kube.released(pvc, None) for pvc in existing]):
                    return None
                for pvc in existing:
                    if not pvc["metadata"].get("deletionTimestamp"):
                        await self.kube.delete_pvc(pvc)
                if job is not None:
                    await self.kube.delete_released_ca_pods(job, existing)
            elif job is not None:
                await self.kube.delete_job(job)
            else:
                await self.kube.create_job(ca_job(self.settings))
            return None
        if deleting:
            # Never heal a partially deleting live attempt by creating another half.
            return None
        assert job is not None
        for role in CA_ROLES:
            if claims[role] is None:
                await self.kube.create_pvc(ca_pvc(self.settings, role, job["metadata"]["uid"]))
                return None
        if (
            not complete
            or job.get("status", {}).get("active", 0)
            or job.get("status", {}).get("terminating", 0)
            or any(pvc.get("status", {}).get("phase") != "Bound" for pvc in existing)
        ):
            return None
        if not all([await self.kube.released(pvc, job) for pvc in existing]):
            return None
        # A pair is returned only after both release proofs and fresh UID/RV checks
        # for the retained Job and BOTH claims. Bound alone is never sufficient.
        current_job, current = await self._observe()
        if not same_observation(current_job, job) or not all(
            same_observation(current[pvc["metadata"]["labels"][CA_ROLE]], pvc) for pvc in existing
        ):
            return None
        return {pvc["metadata"]["labels"][CA_ROLE]: pvc for pvc in existing}
