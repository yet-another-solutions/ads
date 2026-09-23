"""Fixed-name publication from verified custody, without key regeneration."""

from __future__ import annotations

from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_objects import PairBinding, compute_identity, control_service
from ads_sandbox_manager.relay_inputs import (
    INPUT_ROLES,
    input_identity,
    input_secret,
    validate_payload,
)
from ads_sandbox_manager.relay_key_kube import RelayKeyAdapter


class RelayInputAdapter:
    def __init__(self, kube: KubeClient) -> None:
        self.kube = kube
        self.custody = RelayKeyAdapter(kube)

    @property
    def namespace(self) -> str:
        return self.kube.settings.namespace

    @property
    def golden_version(self) -> str:
        return self.kube.settings.golden_version

    async def dependencies(
        self,
        pair: PairBinding,
        pod_uids: dict[str, str],
        service_uid: str,
    ) -> str:
        """Observe exact recorded identities; no create/adoption or readiness verdict."""
        if set(pod_uids) != set(INPUT_ROLES) or any(
            not isinstance(uid, str) or not uid.strip() for uid in (*pod_uids.values(), service_uid)
        ):
            raise ValueError("recorded relay dependencies required")
        for role in INPUT_ROLES:
            desired = compute_identity(self.kube.settings, pair, role)
            observed = await self.kube._get(
                self.kube.core.read_namespaced_pod, desired["metadata"]["name"]
            )
            if observed is None:
                raise RuntimeError("bound relay Pod disappeared")
            PairControlAdapter._identity(observed, desired, pod_uids[role])
            if observed["metadata"].get("deletionTimestamp"):
                raise RuntimeError("relay Pod is deleting")
        desired = control_service(self.kube.settings, pair, "egress-relay")
        observed = await self.kube._get(
            self.kube.core.read_namespaced_service, desired["metadata"]["name"]
        )
        if observed is None:
            raise RuntimeError("bound relay Service disappeared")
        PairControlAdapter._identity(observed, desired, service_uid)
        if observed["metadata"].get("deletionTimestamp") or not PairControlAdapter._spec_matches(
            observed, desired
        ):
            raise RuntimeError("deleting or incompatible relay Service")
        return str(observed["spec"]["clusterIP"])

    async def _desired(self, pair: PairBinding, role: str, payload: Object) -> Object:
        validate_payload(pair, role, payload)
        address = await self.dependencies(pair, payload["pod_uids"], payload["service_uid"])
        if address != payload["service_ipv4"]:
            raise RuntimeError("committed relay Service address changed")
        keys = await self.custody.load(pair, payload["public_keys"], payload["custody_uid"])
        return input_secret(self.kube.settings, pair, role, payload, keys)

    async def _read(
        self,
        pair: PairBinding,
        role: str,
        desired: Object,
        uid: str | None,
    ) -> str | None:
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid relay input UID")
        try:
            observed = await self.kube._get(
                self.kube.core.read_namespaced_secret, desired["metadata"]["name"]
            )
        except Exception:
            raise RuntimeError("relay input read failed") from None
        if observed is None:
            if uid is not None:
                raise RuntimeError("bound relay input disappeared")
            return None
        result = PairControlAdapter._identity(
            observed, input_identity(self.kube.settings, pair, role), uid
        )
        if (
            observed["metadata"].get("deletionTimestamp")
            or observed.get("type") != "Opaque"
            or observed.get("immutable") is not True
            or observed.get("stringData")
            or observed.get("data") != desired["data"]
        ):
            raise RuntimeError("incompatible immutable relay input")
        return result

    async def create(self, pair: PairBinding, role: str, payload: Object) -> str:
        """One original reservation only; a conflict is verified, never overwritten."""
        desired = await self._desired(pair, role, payload)
        try:
            await self.kube._call(
                self.kube.core.create_namespaced_secret, self.namespace, body=desired
            )
        except ApiException as exc:
            if exc.status != 409:
                raise RuntimeError("relay input create failed") from None
        except Exception:
            raise RuntimeError("relay input create failed") from None
        uid = await self._read(pair, role, desired, None)
        if uid is None:
            raise RuntimeError("relay input create is not observable")
        return uid

    async def observe(
        self,
        pair: PairBinding,
        role: str,
        payload: Object,
        uid: str | None,
    ) -> str | None:
        return await self._read(pair, role, await self._desired(pair, role, payload), uid)
