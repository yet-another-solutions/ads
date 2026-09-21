from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from ads_sandbox_manager.ca_objects import CA_NAME, ca_job, ca_pvc
from ads_sandbox_manager.config import CaSettings
from test_kube_release import api as api

pytestmark = pytest.mark.anyio


def setup_pair(api, manager_settings):
    settings = replace(manager_settings, ca=CaSettings("image", "signer", "extra"))
    job = ca_job(settings)
    job["metadata"].update(uid="job-uid", resourceVersion="1")
    job["status"] = {"conditions": [{"type": "Failed", "status": "True"}]}
    claims = [ca_pvc(settings, role, "job-uid") for role in ("public", "private")]
    for role, pvc in zip(("public", "private"), claims, strict=True):
        pvc["metadata"].update(uid=f"{role}-uid", resourceVersion="1", deletionTimestamp="now")
        pvc["spec"]["volumeName"] = f"pv-{role}"
        pvc["status"] = {"phase": "Bound"}
    current = {p["metadata"]["name"]: deepcopy(p) for p in claims}
    api.batch.read_namespaced_job.return_value = deepcopy(job)
    api.core.read_namespaced_persistent_volume_claim.side_effect = lambda name, *a, **kw: current[
        name
    ]
    pod = api.core.list_namespaced_pod.return_value["items"][0]
    pod["metadata"]["name"] = "ca-pod"
    pod["spec"]["volumes"] = [
        {"persistentVolumeClaim": {"claimName": pvc["metadata"]["name"]}} for pvc in claims
    ]

    def pv(name, **kwargs):
        role = name.removeprefix("pv-")
        return {
            "spec": {
                "claimRef": {
                    "uid": f"{role}-uid",
                    "name": f"{CA_NAME}-{role}",
                    "namespace": manager_settings.namespace,
                },
                "csi": {"driver": "example.csi.test", "volumeHandle": role},
            }
        }

    api.core.read_persistent_volume.side_effect = pv
    return job, claims, current, pod


async def test_release_checks_use_observed_ca_claim_not_golden_name(api, manager_settings):
    job, claims, _, _ = setup_pair(api, manager_settings)
    for pvc in claims:
        assert await api.released(pvc, job)
    api.core.read_node.return_value["status"]["volumesInUse"] = [
        "kubernetes.io/csi/example.csi.test^private"
    ]
    assert await api.released(claims[0], job)
    assert not await api.released(claims[1], job)


@pytest.mark.parametrize(
    "blocked",
    [
        None,
        "job-replaced",
        "job-progress",
        "public-used",
        "private-used",
        "private-replaced",
        "private-not-deleting",
        "attempt",
        "running",
        "foreign-pod",
    ],
)
async def test_pair_pod_cleanup_requires_both_outputs_released_and_deleting(
    api, manager_settings, blocked
):
    job, claims, current, pod = setup_pair(api, manager_settings)
    if blocked == "job-replaced":
        api.batch.read_namespaced_job.return_value["metadata"]["resourceVersion"] = "2"
    elif blocked == "job-progress":
        api.batch.read_namespaced_job.return_value["status"] = {}
    elif blocked in ("public-used", "private-used"):
        role = blocked.removesuffix("-used")
        api.core.read_node.return_value["status"]["volumesInUse"] = [
            f"kubernetes.io/csi/example.csi.test^{role}"
        ]
    elif blocked == "private-replaced":
        current[f"{CA_NAME}-private"]["metadata"]["uid"] = "replacement"
    elif blocked == "private-not-deleting":
        del current[f"{CA_NAME}-private"]["metadata"]["deletionTimestamp"]
    elif blocked == "attempt":
        current[f"{CA_NAME}-private"]["metadata"]["labels"]["ads.io/golden-job-uid"] = "other"
    elif blocked == "running":
        pod["status"]["phase"] = "Running"
    elif blocked == "foreign-pod":
        pod["metadata"]["ownerReferences"][0]["uid"] = "other"
    await api.delete_released_ca_pods(job, claims)
    if blocked:
        api.core.delete_namespaced_pod.assert_not_called()
    else:
        call = api.core.delete_namespaced_pod.call_args
        assert call.args == ("ca-pod", manager_settings.namespace)
        assert call.kwargs["body"]["preconditions"] == {"uid": "pod-uid", "resourceVersion": "7"}
    api.batch.delete_namespaced_job.assert_not_called()
    api.core.delete_namespaced_persistent_volume_claim.assert_not_called()


async def test_complete_partial_pair_can_release_terminal_pod_protection(api, manager_settings):
    job, claims, _, _ = setup_pair(api, manager_settings)
    job["status"]["conditions"][0]["type"] = "Complete"
    api.batch.read_namespaced_job.return_value = deepcopy(job)
    await api.delete_released_ca_pods(job, claims)
    api.core.delete_namespaced_pod.assert_called_once()
