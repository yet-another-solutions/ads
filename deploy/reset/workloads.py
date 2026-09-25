"""Explicit UID-bound workload fencing for the operator-run reset coordinator."""

from __future__ import annotations

import time
from typing import Any

from kubernetes import client, config
from protected import PreservationError

CONTROLLERS = {"ads-sandbox-manager", "ads-sandbox-mcp"}
SERVICES = {"ads", "ads-engine", "ads-preferences", *CONTROLLERS}


class Workloads:
    def __init__(self, namespace: str, context: str, definitions: list[dict[str, Any]]):
        if not namespace or not context or not definitions:
            raise PreservationError("explicit cluster context, namespace and workloads required")
        if any(
            set(item) != {"service", "kind", "name"}
            or item["service"] not in SERVICES
            or item["kind"] not in ("Deployment", "StatefulSet")
            or not item["name"]
            for item in definitions
        ) or len({(item["kind"], item["name"]) for item in definitions}) != len(definitions):
            raise PreservationError("invalid or duplicate reset workload")
        configuration = client.Configuration()
        config.load_kube_config(context=context, client_configuration=configuration)
        if not configuration.verify_ssl:
            raise PreservationError("reset Kubernetes TLS verification is mandatory")
        self.api = client.ApiClient(configuration)
        self.apps, self.core = client.AppsV1Api(self.api), client.CoreV1Api(self.api)
        self.autoscaling = client.AutoscalingV2Api(self.api)
        self.namespace, self.definitions = namespace, definitions

    def close(self):
        self.api.close()

    def _object(self, item):
        operation = getattr(
            self.apps,
            "read_namespaced_" + ("deployment" if item["kind"] == "Deployment" else "stateful_set"),
        )
        return self.api.sanitize_for_serialization(
            operation(item["name"], self.namespace, _request_timeout=20)
        )

    def _autoscalers(self):
        response = self.autoscaling.list_namespaced_horizontal_pod_autoscaler(
            self.namespace, _request_timeout=20
        )
        return self.api.sanitize_for_serialization(response)["items"]

    def snapshot(self):
        try:
            namespace = self.core.read_namespace(self.namespace, _request_timeout=20)
            hpas, result = self._autoscalers(), []
            for definition in self.definitions:
                obj = self._object(definition)
                meta, spec = obj["metadata"], obj["spec"]
                if (
                    meta.get("ownerReferences")
                    or meta.get("deletionTimestamp")
                    or any(
                        hpa["spec"]["scaleTargetRef"]["name"] == definition["name"]
                        and hpa["spec"]["scaleTargetRef"]["kind"] == definition["kind"]
                        for hpa in hpas
                    )
                ):
                    raise PreservationError("operator-owned or autoscaled reset workload")
                selector = spec["selector"]
                if selector.get("matchExpressions") or not selector.get("matchLabels"):
                    raise PreservationError("exact workload label selector required")
                result.append(
                    {
                        **definition,
                        "uid": meta["uid"],
                        "replicas": spec.get("replicas", 1),
                        "selector": selector["matchLabels"],
                    }
                )
            return {
                "namespace": self.namespace,
                "namespace_uid": namespace.metadata.uid,
                "items": result,
            }
        except Exception:
            raise PreservationError("workload scope discovery failed") from None

    def _identity(self, captured):
        namespace = self.core.read_namespace(self.namespace, _request_timeout=20)
        if (
            captured["namespace"] != self.namespace
            or namespace.metadata.uid != captured["namespace_uid"]
        ):
            raise PreservationError("reset namespace identity changed")
        if [
            {key: item[key] for key in ("service", "kind", "name")} for item in captured["items"]
        ] != self.definitions:
            raise PreservationError("captured reset workload scope changed")

    def set_replicas(self, captured, item, replicas):
        try:
            self._identity(captured)
            obj = self._object(item)
            if obj["metadata"]["uid"] != item["uid"]:
                raise PreservationError("reset workload replaced")
            body = [
                {"op": "test", "path": "/metadata/uid", "value": item["uid"]},
                {
                    "op": "test",
                    "path": "/metadata/resourceVersion",
                    "value": obj["metadata"]["resourceVersion"],
                },
                {"op": "replace", "path": "/spec/replicas", "value": replicas},
            ]
            method = getattr(
                self.apps,
                "patch_namespaced_"
                + ("deployment" if item["kind"] == "Deployment" else "stateful_set"),
            )
            method(item["name"], self.namespace, body, _request_timeout=20)
        except Exception:
            raise PreservationError("exact workload scaling failed; do not reset") from None

    def fenced(self, captured, *, except_services=frozenset()):
        try:
            self._identity(captured)
            hpas = self._autoscalers()
            for item in captured["items"]:
                if item["service"] in except_services:
                    continue
                obj = self._object(item)
                if (
                    obj["metadata"]["uid"] != item["uid"]
                    or obj["metadata"].get("ownerReferences")
                    or obj["spec"].get("replicas") != 0
                    or obj.get("status", {}).get("replicas", 0) != 0
                    or obj["spec"]["selector"].get("matchLabels") != item["selector"]
                    or any(
                        hpa["spec"]["scaleTargetRef"]["name"] == item["name"]
                        and hpa["spec"]["scaleTargetRef"]["kind"] == item["kind"]
                        for hpa in hpas
                    )
                ):
                    return False
                selector = ",".join(
                    f"{key}={value}" for key, value in sorted(item["selector"].items())
                )
                if self.core.list_namespaced_pod(
                    self.namespace,
                    label_selector=selector,
                    _request_timeout=20,
                ).items:
                    return False
            return True
        except Exception:
            raise PreservationError("workload quiescence verification failed") from None

    def pause(self, captured):
        for item in captured["items"]:
            self.set_replicas(captured, item, 0)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if self.fenced(captured):
                return
            time.sleep(1)
        raise PreservationError("writers did not quiesce; reset remains blocked")

    def start_preferences(self, captured):
        candidates = [item for item in captured["items"] if item["service"] == "ads-preferences"]
        if len(candidates) != 1:
            raise PreservationError("exact preferences restoration workload required")
        self.set_replicas(captured, candidates[0], max(1, candidates[0]["replicas"]))
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            observed = self._object(candidates[0])
            if observed["metadata"]["uid"] != candidates[0]["uid"]:
                raise PreservationError("preferences workload replaced during restoration")
            status = observed.get("status", {})
            key = "availableReplicas" if candidates[0]["kind"] == "Deployment" else "readyReplicas"
            if status.get(key, 0) >= 1:
                return
            time.sleep(1)
        raise PreservationError("preferences restoration API did not become ready")

    def resume(self, captured, *, quarantine: bool):
        for item in captured["items"]:
            if quarantine and item["service"] in CONTROLLERS:
                continue
            self.set_replicas(captured, item, item["replicas"])
