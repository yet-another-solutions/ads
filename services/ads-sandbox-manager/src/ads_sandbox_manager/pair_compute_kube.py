"""Fixed Pod creation with exact retained-volume and control identity checks."""

from __future__ import annotations

from copy import deepcopy
from typing import cast
from uuid import UUID

from kubernetes.client.exceptions import ApiException
from kubernetes.utils.quantity import parse_quantity

from ads_sandbox_manager.egress_state_kube import EgressStateAdapter
from ads_sandbox_manager.egress_state_store import state_from_snapshot
from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.objects import COMPONENT, JOB_UID, VERSION, Object
from ads_sandbox_manager.pair_compute_inputs import compute_manifest, validate_payload
from ads_sandbox_manager.pair_kube import ControlKind, PairControlAdapter
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.pair_store import CONTROL_RESOURCES, resource_key
from ads_sandbox_manager.session_objects import (
    CA_CONSUMER,
    CA_CONSUMER_ROLE,
    CA_SOURCE_UID,
    SANDBOX,
    SESSION,
    ca_consumer_name,
    session_name,
)


class PairComputeAdapter:
    def __init__(self, kube: KubeClient, controls: PairControlAdapter) -> None:
        self.kube, self.controls = kube, controls

    @property
    def namespace(self) -> str:
        return self.kube.settings.namespace

    @property
    def golden_version(self) -> str:
        return self.kube.settings.golden_version

    async def _dependencies(
        self,
        pair: PairBinding,
        role: str,
        payload: Object,
        controls: dict[str, str | None],
    ) -> None:
        if (self.controls.namespace, self.controls.golden_version) != (
            self.namespace,
            self.golden_version,
        ):
            raise RuntimeError("compute control configuration changed")
        if set(controls) != {resource_key(*item) for item in CONTROL_RESOURCES}:
            raise RuntimeError("complete recorded control identities required")
        if controls != payload["control_uids"]:
            raise RuntimeError("committed compute control identities changed")
        for kind, member in CONTROL_RESOURCES:
            uid = controls[resource_key(kind, member)]
            if not isinstance(uid, str) or not uid.strip():
                raise RuntimeError("complete recorded control identities required")
            # A supplied UID makes ensure strictly read-only, including on 404.
            await self.controls.ensure(pair, cast(ControlKind, kind), member, uid)
        if role == "egress":
            state = state_from_snapshot(payload["state"])
            await EgressStateAdapter(self.kube).observe_volume(state)
            expected = tuple(
                (
                    ca_consumer_name(pair.sandbox_id, member),
                    payload["ca_clones"][member],
                    {
                        COMPONENT: CA_CONSUMER,
                        CA_CONSUMER_ROLE: member,
                        CA_SOURCE_UID: payload["ca_sources"][source],
                        JOB_UID: payload["ca_attempt"],
                    },
                )
                for member, source in (("egress", "public"), ("key", "private"))
            )
        elif role == "guest":
            expected = (
                (
                    session_name(UUID(payload["pvc_id"])),
                    payload["pvc_uid"],
                    {COMPONENT: "ads-sandbox"},
                ),
                (
                    ca_consumer_name(pair.sandbox_id, "guest"),
                    payload["ca_guest_uid"],
                    {
                        COMPONENT: CA_CONSUMER,
                        CA_CONSUMER_ROLE: "guest",
                        CA_SOURCE_UID: payload["ca_source_uid"],
                        JOB_UID: payload["ca_attempt"],
                    },
                ),
            )
        else:
            return
        for name, uid, labels in expected:
            desired = {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {
                    "name": name,
                    "namespace": self.namespace,
                    "labels": {
                        SESSION: str(pair.session_id),
                        SANDBOX: str(pair.sandbox_id),
                        VERSION: payload["golden_version"],
                        **labels,
                    },
                },
            }
            observed = await self.kube.named_pvc(name)
            if observed is None:
                raise RuntimeError("bound compute volume disappeared")
            PairControlAdapter._identity(observed, desired, uid)
            spec = observed.get("spec", {})
            if (
                observed["metadata"].get("deletionTimestamp")
                or observed.get("status", {}).get("phase") == "Lost"
                or spec.get("volumeMode") != "Block"
                or spec.get("storageClassName") != "sandbox-block"
                or spec.get("accessModes") != ["ReadWriteOnce"]
            ):
                raise RuntimeError("deleting or incompatible compute volume")

    @staticmethod
    def _spec_matches(observed: Object, desired: Object) -> bool:
        """Accept explicit API defaults only, not additive execution authority."""
        actual, expected = deepcopy(observed.get("spec", {})), desired["spec"]
        for field, default in (
            ("dnsPolicy", "ClusterFirst"),
            ("schedulerName", "default-scheduler"),
            ("serviceAccountName", "default"),
            ("serviceAccount", "default"),
            ("securityContext", {}),
            ("priority", 0),
            ("preemptionPolicy", "PreemptLowerPriority"),
        ):
            if field not in expected and actual.pop(field, default) != default:
                return False
        node = actual.pop("nodeName", None)
        if node is not None and (not isinstance(node, str) or not node.strip()):
            return False
        for field in ("tolerations", "imagePullSecrets"):
            if not expected[field]:
                actual.setdefault(field, [])
        # Default admission tolerations do not grant a new placement selector.
        tolerations = actual.get("tolerations", [])
        if isinstance(tolerations, list):
            actual["tolerations"] = [
                t
                for t in tolerations
                if t in expected["tolerations"]
                or t
                not in [
                    {
                        "key": key,
                        "operator": "Exists",
                        "effect": "NoExecute",
                        "tolerationSeconds": 300,
                    }
                    for key in ("node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable")
                ]
            ]
        containers = actual.get("containers")
        if not isinstance(containers, list) or len(containers) != len(expected["containers"]):
            return False
        for container, wanted in zip(containers, expected["containers"], strict=True):
            if not isinstance(container, dict):
                return False
            for key, default in (
                ("terminationMessagePath", "/dev/termination-log"),
                ("terminationMessagePolicy", "File"),
                ("imagePullPolicy", "IfNotPresent"),
            ):
                if key not in wanted and container.pop(key, default) != default:
                    return False
            for probe in ("readinessProbe", "livenessProbe"):
                if probe not in wanted:
                    continue
                value = container.get(probe)
                if not isinstance(value, dict):
                    return False
                for key, default in (
                    ("initialDelaySeconds", 0),
                    ("timeoutSeconds", 1),
                    ("periodSeconds", 10),
                    ("successThreshold", 1),
                    ("failureThreshold", 3),
                ):
                    if key not in wanted[probe] and value.pop(key, default) != default:
                        return False
            resources = container.get("resources", {})
            required = deepcopy(wanted.get("resources", {}))
            default_requests = "requests" not in required and "requests" in resources
            if default_requests:
                required["requests"] = required.get("limits", {})
            if set(resources) != set(required):
                return False
            try:
                for direction, quantities in required.items():
                    if set(resources[direction]) != set(quantities):
                        return False
                    for name, value in quantities.items():
                        if parse_quantity(resources[direction][name]) != parse_quantity(value):
                            return False
                        resources[direction][name] = value
            except (ValueError, TypeError, KeyError):
                return False
            if default_requests:
                resources.pop("requests")
        for volume, wanted in zip(
            actual.get("volumes", []), expected.get("volumes", []), strict=False
        ):
            pvc = volume.get("persistentVolumeClaim")
            if isinstance(pvc, dict) and "readOnly" not in wanted.get("persistentVolumeClaim", {}):
                if pvc.pop("readOnly", False) is not False:
                    return False
        return bool(actual == expected)

    async def observe(
        self,
        pair: PairBinding,
        role: str,
        payload: Object,
        controls: dict[str, str | None],
        uid: str | None,
    ) -> str | None:
        validate_payload(role, payload)
        desired = compute_manifest(self.kube.settings, pair, role, payload)
        await self._dependencies(pair, role, payload, controls)
        observed = await self.kube._get(
            self.kube.core.read_namespaced_pod, desired["metadata"]["name"]
        )
        if observed is None:
            if uid is not None:
                raise RuntimeError("bound pair Pod disappeared")
            return None
        result = PairControlAdapter._identity(observed, desired, uid)
        if (
            observed["metadata"].get("deletionTimestamp")
            or observed["metadata"].get("annotations")
            or not self._spec_matches(observed, desired)
        ):
            raise RuntimeError("deleting or incompatible pair Pod")
        if role == "egress":
            # Stateful custody and both CA clones must still be the committed
            # dependencies after the Pod read, not only before it.
            await self._dependencies(pair, role, payload, controls)
        return result

    async def create(
        self,
        pair: PairBinding,
        role: str,
        payload: Object,
        controls: dict[str, str | None],
    ) -> str:
        validate_payload(role, payload)
        desired = compute_manifest(self.kube.settings, pair, role, payload)
        await self._dependencies(pair, role, payload, controls)
        try:
            await self.kube._call(
                self.kube.core.create_namespaced_pod, self.namespace, body=desired
            )
        except ApiException as exc:
            if exc.status != 409:
                raise
        # Verify dependencies again after creation, never settle an incompatible result.
        uid = await self.observe(pair, role, payload, controls, None)
        if uid is None:
            raise RuntimeError("pair Pod create is not observable")
        return uid
