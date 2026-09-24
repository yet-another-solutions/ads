"""Fixed control operations and read-only compute ownership observation."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Literal, cast

from kubernetes import client
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.egress_state_objects import identity as egress_state_identity
from ads_sandbox_manager.egress_state_store import state_from_snapshot
from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_ipc_inputs import ipc_identity
from ads_sandbox_manager.pair_objects import (
    COMPUTE_ROLES,
    PairBinding,
    compute_identity,
    control_ingress,
    control_service,
    pod_group,
)
from ads_sandbox_manager.pair_volume_inputs import volume_manifest
from ads_sandbox_manager.relay_inputs import input_identity
from ads_sandbox_manager.relay_keys import custody_identity

ControlKind = Literal["PodGroup", "Service", "NetworkPolicy"]


class PairControlAdapter:
    """No readiness verdict, namespace discovery, patch or exec.

    Custody cleanup reads one captured Secret name for metadata only. It neither
    returns key material nor discovers, copies or reads platform signing Secrets.

    The lifecycle caller must commit pair/generation intent before ensure(), then
    persist the returned UID before advancing. A recorded UID never authorizes
    recreating an absent object or adopting a replacement with the same name.
    """

    def __init__(self, kube: KubeClient) -> None:
        self.kube = kube
        self.networking = client.NetworkingV1Api(kube.api_client)
        self.custom = client.CustomObjectsApi(kube.api_client)

    @property
    def namespace(self) -> str:
        return self.kube.settings.namespace

    @property
    def golden_version(self) -> str:
        return self.kube.settings.golden_version

    def _desired(self, pair: PairBinding, kind: ControlKind, role: str) -> Object:
        builders = {
            "PodGroup": pod_group,
            "Service": control_service,
            "NetworkPolicy": control_ingress,
        }
        if kind not in builders:
            raise ValueError("unsupported pair control resource")
        return builders[kind](self.kube.settings, pair, role)

    async def _request(self, operation: str, desired: Object, body: Object | None = None) -> Object:
        kind = desired["kind"]
        namespace = self.kube.settings.namespace
        if kind == "PodGroup":
            method = getattr(self.custom, operation + "_namespaced_custom_object")
            arguments = ["scheduling.k8s.io", "v1alpha2", namespace, "podgroups"]
        else:
            api, resource = (
                (self.kube.core, "service")
                if kind == "Service"
                else (self.networking, "network_policy")
            )
            verb = "read" if operation == "get" else operation
            method = getattr(api, verb + "_namespaced_" + resource)
            arguments = (
                [namespace]
                if operation == "create"
                else [
                    desired["metadata"]["name"],
                    namespace,
                ]
            )
        if kind == "PodGroup" and operation != "create":
            arguments.append(desired["metadata"]["name"])
        kwargs = {"body": body} if body is not None else {}
        return cast(Object, await self.kube._call(method, *arguments, **kwargs))

    async def _read(self, desired: Object) -> Object | None:
        try:
            return await self._request("get", desired)
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    @staticmethod
    def _identity(observed: Object, desired: Object, uid: str | None) -> str:
        meta, expected = observed.get("metadata", {}), desired["metadata"]
        if (
            observed.get("kind") != desired["kind"]
            or observed.get("apiVersion") != desired["apiVersion"]
            or meta.get("name") != expected["name"]
            or meta.get("namespace") != expected["namespace"]
            or not isinstance(meta.get("uid"), str)
            or not meta["uid"].strip()
            or not isinstance(meta.get("resourceVersion"), str)
            or not meta["resourceVersion"].strip()
            or meta.get("ownerReferences")
            or any(meta.get("labels", {}).get(k) != v for k, v in expected["labels"].items())
            or (uid is not None and meta["uid"] != uid)
        ):
            raise RuntimeError("foreign, replaced, or unfenced pair resource")
        return cast(str, meta["uid"])

    @staticmethod
    def _spec_matches(observed: Object, desired: Object) -> bool:
        actual = dict(observed.get("spec", {}))
        if desired["kind"] == "Service":
            # Permit only API allocation/defaulting, never additive exposure,
            # changed selectors, widened ports, or alternate routing settings.
            cluster_ip = actual.pop("clusterIP", None)
            try:
                ip_address(cluster_ip)
            except (ValueError, TypeError):
                return False
            cluster_ips = actual.pop("clusterIPs", None)
            if cluster_ips is not None and (
                not isinstance(cluster_ips, list) or not cluster_ips or cluster_ips[0] != cluster_ip
            ):
                return False
            for field, default in (
                ("sessionAffinity", "None"),
                ("internalTrafficPolicy", "Cluster"),
                ("ipFamilyPolicy", "SingleStack"),
            ):
                if actual.pop(field, default) != default:
                    return False
            families = actual.pop("ipFamilies", None)
            if families is not None and families != [f"IPv{ip_address(cluster_ip).version}"]:
                return False
            if cluster_ips is not None and len(cluster_ips) != 1:
                return False
        return bool(actual == desired["spec"])

    async def ensure(
        self, pair: PairBinding, kind: ControlKind, role: str, uid: str | None = None
    ) -> str:
        desired = self._desired(pair, kind, role)
        observed = await self._read(desired)
        if observed is None:
            if uid is not None:
                raise RuntimeError("bound pair control resource disappeared")
            try:
                await self._request("create", desired, desired)
            except ApiException as exc:
                if exc.status != 409:
                    raise
            observed = await self._read(desired)
        if observed is None:
            raise RuntimeError("pair control create is not observable")
        result = self._identity(observed, desired, uid)
        if observed["metadata"].get("deletionTimestamp") or not self._spec_matches(
            observed, desired
        ):
            raise RuntimeError("deleting or incompatible pair control resource")
        return result

    async def delete(self, pair: PairBinding, kind: ControlKind, role: str, uid: str) -> bool:
        """True only on observed absence; a delete response is not completion."""
        if not isinstance(uid, str) or not uid:
            raise ValueError("a recorded UID is required for pair control cleanup")
        desired = self._desired(pair, kind, role)
        observed = await self._read(desired)
        if observed is None:
            return True
        self._identity(observed, desired, uid)
        if not observed["metadata"].get("deletionTimestamp"):
            try:
                await self._request(
                    "delete",
                    desired,
                    {
                        "apiVersion": "v1",
                        "kind": "DeleteOptions",
                        "propagationPolicy": "Foreground",
                        "preconditions": {
                            "uid": uid,
                            "resourceVersion": observed["metadata"]["resourceVersion"],
                        },
                    },
                )
            except ApiException as exc:
                if exc.status == 409:
                    return False
                if exc.status != 404:
                    raise
        remaining = await self._read(desired)
        if remaining is None:
            return True
        self._identity(remaining, desired, uid)
        return False

    async def observe(
        self, pair: PairBinding, kind: ControlKind, role: str, uid: str | None = None
    ) -> str | None:
        """Observe captured intent, including ambiguous creates; never create.

        Terminating or spec-drifted owned objects still need exact cleanup.
        None is only this read's absence, not runtime-release/retirement proof.
        """
        desired = self._desired(pair, kind, role)
        observed = await self._read(desired)
        return None if observed is None else self._identity(observed, desired, uid)

    async def observe_ipc(self, pair: PairBinding, role: str, uid: str | None) -> str | None:
        """Metadata-only ownership capture, never usability or runtime release."""
        desired = ipc_identity(self.kube.settings, pair, role)
        method = (
            self.kube.core.read_namespaced_persistent_volume_claim
            if role == "volume"
            else self.kube.core.read_namespaced_pod
        )
        try:
            observed = await self.kube._get(method, desired["metadata"]["name"])
        except Exception:
            raise RuntimeError("paired IPC cleanup read failed") from None
        return None if observed is None else self._identity(observed, desired, uid)

    async def observe_clone(
        self, pair: PairBinding, role: str, payload: Object, uid: str | None
    ) -> str | None:
        """Capture only committed clone ownership, without touching source services."""
        desired = volume_manifest(self.kube.settings, pair, role, payload)
        try:
            observed = await self.kube.named_pvc(desired["metadata"]["name"])
        except Exception:
            raise RuntimeError("paired clone cleanup read failed") from None
        return None if observed is None else self._identity(observed, desired, uid)

    async def observe_compute(
        self, pair: PairBinding, role: str, uid: str | None = None
    ) -> str | None:
        """Read exactly one fixed Pod name; never list, create, mutate or delete.

        Owned terminating/spec-drifted Pods remain cleanup obligations. Neither
        a captured UID nor 404 supplies runtime identity, readiness, dispatch
        settlement or release evidence. Controller-owned Pods are not adopted.
        """
        desired = compute_identity(self.kube.settings, pair, role)
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid recorded pair compute UID")
        observed = await self.kube._get(
            self.kube.core.read_namespaced_pod, desired["metadata"]["name"]
        )
        return None if observed is None else self._identity(observed, desired, uid)

    async def compute_node(self, pair: PairBinding, uids: dict[str, str | None]) -> str:
        """Observe one placement for all four exact Pods, never derive it from absence.

        The node owner must still attest the actual runtime and inventory. Two
        complete reads reject disappearance/replacement while resolving placement;
        neither read supplies runtime-release or readiness evidence.
        """
        if (
            not isinstance(uids, dict)
            or set(uids) != {f"Pod/{role}" for role in COMPUTE_ROLES}
            or any(not isinstance(uid, str) or not uid.strip() for uid in uids.values())
            or len(set(uids.values())) != len(COMPUTE_ROLES)
        ):
            raise ValueError("four distinct recorded pair Pod UIDs required")
        uids = dict(uids)
        node: str | None = None
        for _ in range(2):
            for role in COMPUTE_ROLES:
                desired = compute_identity(self.kube.settings, pair, role)
                observed = await self.kube._get(
                    self.kube.core.read_namespaced_pod, desired["metadata"]["name"]
                )
                if observed is None:
                    raise RuntimeError("exact pair Pod placement unavailable")
                self._identity(observed, desired, uids[f"Pod/{role}"])
                actual = observed.get("spec", {}).get("nodeName")
                if not isinstance(actual, str) or not actual.strip():
                    raise RuntimeError("exact pair Pod is not assigned to a node")
                if node is not None and node != actual:
                    raise RuntimeError("pair Pod placement changed or spans nodes")
                node = actual
        assert node is not None
        return node

    async def delete_compute(self, pair: PairBinding, role: str, uid: str, *, node: str) -> bool:
        """UID/RV-fenced removal; True means API absence only, never runtime release.

        The caller must already have committed settled-writer ownership and
        original node capture. This adapter does not establish that authority.
        Keep policies, volumes and keys until separate positive release proof.
        No force deletion, grace-period override, finalizer removal or recreation.
        """
        desired = compute_identity(self.kube.settings, pair, role)
        if (
            not isinstance(uid, str)
            or not uid.strip()
            or not isinstance(node, str)
            or not node.strip()
        ):
            raise ValueError("recorded Pod UID and captured node required")
        name = desired["metadata"]["name"]
        observed = await self.kube._get(self.kube.core.read_namespaced_pod, name)
        if observed is None:
            return True
        self._identity(observed, desired, uid)
        if observed.get("spec", {}).get("nodeName") != node:
            raise RuntimeError("pair Pod moved away from captured node")
        if not observed["metadata"].get("deletionTimestamp"):
            try:
                await self.kube._call(
                    self.kube.core.delete_namespaced_pod,
                    name,
                    self.namespace,
                    body={
                        "apiVersion": "v1",
                        "kind": "DeleteOptions",
                        "propagationPolicy": "Foreground",
                        "preconditions": {
                            "uid": uid,
                            "resourceVersion": observed["metadata"]["resourceVersion"],
                        },
                    },
                )
            except ApiException as exc:
                if exc.status == 409:
                    return False
                if exc.status != 404:
                    raise
        remaining = await self.kube._get(self.kube.core.read_namespaced_pod, name)
        if remaining is None:
            return True
        self._identity(remaining, desired, uid)
        if remaining.get("spec", {}).get("nodeName") != node:
            raise RuntimeError("pair Pod moved away from captured node")
        return False

    async def observe_relay_custody(self, pair: PairBinding, uid: str | None) -> str | None:
        """Owned deleting/drifted Secrets remain obligations, not usable custody."""
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid relay custody UID")
        desired = custody_identity(self.kube.settings, pair)
        try:
            observed = await self.kube._get(
                self.kube.core.read_namespaced_secret, desired["metadata"]["name"]
            )
        except Exception:
            raise RuntimeError("relay custody observation failed") from None
        return None if observed is None else self._identity(observed, desired, uid)

    async def observe_relay_input(
        self,
        pair: PairBinding,
        role: str,
        uid: str | None,
    ) -> str | None:
        """Capture deleting/drifted inputs by metadata, never return secret data."""
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid relay input UID")
        desired = input_identity(self.kube.settings, pair, role)
        try:
            observed = await self.kube._get(
                self.kube.core.read_namespaced_secret, desired["metadata"]["name"]
            )
        except Exception:
            raise RuntimeError("relay input observation failed") from None
        return None if observed is None else self._identity(observed, desired, uid)

    async def observe_egress_state(
        self, snapshot: dict[str, object], role: str, uid: str | None
    ) -> str | None:
        """Observe metadata only; never load key data, PVC contents or create."""
        state = state_from_snapshot(snapshot)
        if state.namespace != self.namespace:
            raise RuntimeError("persistent egress cleanup namespace changed")
        if role not in ("key", "volume"):
            raise ValueError("unsupported persistent egress cleanup role")
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid persistent egress cleanup UID")
        desired = egress_state_identity(state, role)
        if role == "volume":
            desired["metadata"]["labels"]["ads.io/wrapping-custody-uid"] = state.key_uid
        method = (
            self.kube.core.read_namespaced_secret
            if role == "key"
            else self.kube.core.read_namespaced_persistent_volume_claim
        )
        try:
            observed = await self.kube._get(method, desired["metadata"]["name"])
        except Exception:
            raise RuntimeError("persistent egress cleanup observation failed") from None
        return None if observed is None else self._identity(observed, desired, uid)
