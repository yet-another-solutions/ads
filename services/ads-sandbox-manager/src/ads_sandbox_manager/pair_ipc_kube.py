"""Fixed IPC publication with exact pair and PID-volume dependency checks."""

from __future__ import annotations

from copy import deepcopy

from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.egress_state_kube import volume_matches
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_compute_kube import PairComputeAdapter
from ads_sandbox_manager.pair_ipc_inputs import ipc_manifest, validate_ipc_payload
from ads_sandbox_manager.pair_ipc_store import PairIpcRepository
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.relay_input_kube import RelayInputAdapter


class PairIpcAdapter:
    def __init__(self, compute: PairComputeAdapter) -> None:
        self.compute, self.kube = compute, compute.kube
        self.relays = RelayInputAdapter(self.kube)

    def configuration(self, intent: PairIntent) -> None:
        if (intent.namespace, intent.golden_version) != (
            self.kube.settings.namespace,
            self.kube.settings.golden_version,
        ):
            raise RuntimeError("paired IPC configuration changed")

    @staticmethod
    def _deployment_matches(observed: Object, desired: Object) -> bool:
        actual = deepcopy(observed.get("spec", {}))
        expected = desired["spec"]
        annotations = observed.get("metadata", {}).get("annotations") or {}
        if not isinstance(annotations, dict) or set(annotations) - {
            "deployment.kubernetes.io/revision"
        }:
            return False
        revision = annotations.get("deployment.kubernetes.io/revision")
        if revision is not None and (
            not isinstance(revision, str)
            or not revision.isdecimal()
            or str(int(revision)) != revision
            or int(revision) < 1
        ):
            return False
        for field, default in (
            ("revisionHistoryLimit", 10),
            ("progressDeadlineSeconds", 600),
            ("minReadySeconds", 0),
            ("paused", False),
        ):
            if field not in expected and actual.pop(field, default) != default:
                return False
        template = actual.pop("template", {})
        if template.get("metadata") != expected["template"]["metadata"]:
            return False
        pod = template.get("spec", {})
        wanted = expected["template"]["spec"]
        if pod.pop("serviceAccount", wanted["serviceAccountName"]) != wanted["serviceAccountName"]:
            return False
        for field, pod_default in (
            ("restartPolicy", "Always"),
            ("terminationGracePeriodSeconds", 30),
        ):
            if field not in wanted and pod.pop(field, pod_default) != pod_default:
                return False
        for container in pod.get("containers", []):
            for port in container.get("ports", []):
                if port.pop("protocol", "TCP") != "TCP":
                    return False
        for volume in pod.get("volumes", []):
            if "secret" in volume and volume["secret"].pop("defaultMode", 0o644) != 0o644:
                return False
        return bool(
            actual == {key: value for key, value in expected.items() if key != "template"}
            and PairComputeAdapter._spec_matches({"spec": pod}, {"spec": wanted})
        )

    async def _read(
        self, intent: PairIntent, role: str, payload: Object, uid: str | None
    ) -> str | None:
        self.configuration(intent)
        desired = ipc_manifest(self.kube.settings, intent.binding(), role, payload)
        method = (
            self.kube.core.read_namespaced_persistent_volume_claim
            if role == "volume"
            else self.kube.apps.read_namespaced_deployment
        )
        try:
            observed = await self.kube._get(method, desired["metadata"]["name"])
        except Exception:
            raise RuntimeError("paired IPC read failed") from None
        if observed is None:
            if uid is not None:
                raise RuntimeError("bound paired IPC resource disappeared")
            return None
        result = PairControlAdapter._identity(observed, desired, uid)
        if (
            observed["metadata"].get("deletionTimestamp")
            or (
                role == "volume"
                and (
                    observed.get("status", {}).get("phase") == "Lost"
                    or not volume_matches(observed, desired)
                )
            )
            or (role == "deployment" and not self._deployment_matches(observed, desired))
        ):
            raise RuntimeError("deleting or incompatible paired IPC resource")
        return result

    async def _dependencies(self, intent: PairIntent, role: str, payload: Object) -> None:
        self.configuration(intent)
        expected = PairIpcRepository.dependencies(intent)
        if any(payload[key] != value for key, value in expected.items()):
            raise RuntimeError("committed paired IPC dependencies changed")
        for member, committed in intent.compute_payloads.items():
            await self.compute.observe(
                intent.binding(),
                member,
                committed,
                intent.control_uids,
                payload["compute_uids"][f"Pod/{member}"],
            )
        for member, entry in intent.relay_inputs.items():
            await self.relays.observe(intent.binding(), member, entry["payload"], entry["uid"])
        if role == "deployment":
            volume = intent.ipc_resources["volume"]
            if payload["volume_uid"] != volume["uid"] or volume["dispatch"] != "settled":
                raise RuntimeError("committed IPC volume identity changed")
            await self._read(intent, "volume", volume["payload"], payload["volume_uid"])

    async def observe(self, intent: PairIntent, role: str) -> str | None:
        entry = intent.ipc_resources[role]
        validate_ipc_payload(role, entry["payload"])
        await self._dependencies(intent, role, entry["payload"])
        uid = await self._read(intent, role, entry["payload"], entry["uid"])
        await self._dependencies(intent, role, entry["payload"])
        return uid

    async def create(self, intent: PairIntent, role: str) -> str:
        entry = intent.ipc_resources[role]
        if entry["dispatch"] != "inflight" or entry["uid"] is not None:
            raise RuntimeError("original unbound paired IPC dispatch required")
        payload = entry["payload"]
        validate_ipc_payload(role, payload)
        desired = ipc_manifest(self.kube.settings, intent.binding(), role, payload)
        await self._dependencies(intent, role, payload)
        method = (
            self.kube.core.create_namespaced_persistent_volume_claim
            if role == "volume"
            else self.kube.apps.create_namespaced_deployment
        )
        try:
            await self.kube._call(method, intent.namespace, body=desired)
        except ApiException as exc:
            if exc.status != 409:
                raise RuntimeError("paired IPC create failed") from None
        except Exception:
            raise RuntimeError("paired IPC create failed") from None
        uid = await self.observe(intent, role)
        if uid is None:
            raise RuntimeError("paired IPC creation is not observable")
        return uid
