"""Fixed-scope Kubernetes operations for the manager's paired control resources."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Literal, cast

from kubernetes import client
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import (
    PairBinding,
    control_ingress,
    control_service,
    pod_group,
)

ControlKind = Literal["PodGroup", "Service", "NetworkPolicy"]


class PairControlAdapter:
    """No readiness verdict, namespace discovery, patch, exec, or Secret access.

    The lifecycle caller must commit pair/generation intent before ensure(), then
    persist the returned UID before advancing. A recorded UID never authorizes
    recreating an absent object or adopting a replacement with the same name.
    """

    def __init__(self, kube: KubeClient) -> None:
        self.kube = kube
        self.networking = client.NetworkingV1Api(kube.api_client)
        self.custom = client.CustomObjectsApi(kube.api_client)

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
            or not meta["uid"]
            or not isinstance(meta.get("resourceVersion"), str)
            or not meta["resourceVersion"]
            or meta.get("ownerReferences")
            or any(meta.get("labels", {}).get(k) != v for k, v in expected["labels"].items())
            or (uid is not None and meta["uid"] != uid)
        ):
            raise RuntimeError("foreign, replaced, or unfenced pair control resource")
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
