"""Fresh exact clone publication using the existing verified source services."""

from __future__ import annotations

from copy import deepcopy
from typing import Protocol

from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.egress_state_kube import volume_matches
from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.pair_volume_inputs import source_snapshot, volume_manifest, volume_role


class GoldenCloneSource(Protocol):
    async def clone_source(self) -> Object | None: ...


class CaCloneSources(Protocol):
    async def clone_sources(self) -> dict[str, Object] | None: ...


class PairVolumeAdapter:
    def __init__(self, kube: KubeClient, golden: GoldenCloneSource, ca: CaCloneSources) -> None:
        self.kube, self.golden, self.ca = kube, golden, ca

    def configuration(self, intent: PairIntent) -> None:
        if (intent.namespace, intent.golden_version) != (
            self.kube.settings.namespace,
            self.kube.settings.golden_version,
        ):
            raise RuntimeError("paired clone configuration changed")

    async def sources(self, role: str) -> Object:
        volume_role(role)
        try:
            if role == "workspace":
                source = await self.golden.clone_source()
                if source is None:
                    raise RuntimeError
                return {"workspace": source_snapshot(self.kube.settings, "workspace", source)}
            sources = await self.ca.clone_sources()
            if sources is None or set(sources) != {"public", "private"}:
                raise RuntimeError
            result = {
                key: source_snapshot(self.kube.settings, key, value)
                for key, value in sources.items()
            }
            if result["public"]["job_uid"] != result["private"]["job_uid"]:
                raise RuntimeError
            return result
        except Exception:
            raise RuntimeError("verified paired clone sources unavailable") from None

    async def _sources(self, role: str, payload: Object) -> None:
        if await self.sources(role) != payload["sources"]:
            raise RuntimeError("committed paired clone sources changed")

    @staticmethod
    def matches(observed: Object, desired: Object) -> bool:
        actual = deepcopy(observed)
        spec = actual.get("spec", {})
        expected = desired["spec"]["dataSource"]
        for key in ("dataSource", "dataSourceRef"):
            ref = spec.get(key)
            if isinstance(ref, dict) and ref.get("apiGroup") is None:
                ref["apiGroup"] = ""
        reference = spec.pop("dataSourceRef", expected)
        return bool(reference == expected and volume_matches(actual, desired))

    async def observe(self, intent: PairIntent, role: str) -> str | None:
        self.configuration(intent)
        entry = intent.volume_resources[role]
        payload = entry["payload"]
        desired = volume_manifest(self.kube.settings, intent.binding(), role, payload)
        await self._sources(role, payload)
        try:
            observed = await self.kube.named_pvc(desired["metadata"]["name"])
        except Exception:
            raise RuntimeError("paired clone read failed") from None
        if observed is None:
            if entry["uid"] is not None:
                raise RuntimeError("bound paired clone disappeared")
            result = None
        else:
            result = PairControlAdapter._identity(observed, desired, entry["uid"])
            if (
                observed["metadata"].get("deletionTimestamp")
                or observed.get("status", {}).get("phase") == "Lost"
                or not self.matches(observed, desired)
            ):
                raise RuntimeError("deleting or incompatible paired clone")
        await self._sources(role, payload)
        return result

    async def create(self, intent: PairIntent, role: str) -> str:
        self.configuration(intent)
        entry = intent.volume_resources[role]
        if entry["dispatch"] != "inflight" or entry["uid"] is not None:
            raise RuntimeError("original unbound paired clone dispatch required")
        payload = entry["payload"]
        desired = volume_manifest(self.kube.settings, intent.binding(), role, payload)
        await self._sources(role, payload)
        try:
            await self.kube.create_pvc(desired)
        except ApiException as exc:
            if exc.status != 409:
                raise RuntimeError("paired clone create failed") from None
        except Exception:
            raise RuntimeError("paired clone create failed") from None
        result = await self.observe(intent, role)
        if result is None:
            raise RuntimeError("paired clone creation not observable")
        return result
