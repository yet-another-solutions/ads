from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from kubernetes import client
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.objects import golden_job, golden_pvc

pytestmark = pytest.mark.anyio


@pytest.fixture
def api(manager_settings, monkeypatch):
    def configure(*, client_configuration):
        client_configuration.host = "https://kubernetes.test"
        client_configuration.verify_ssl = True

    monkeypatch.setattr("ads_sandbox_manager.kube.config.load_incluster_config", configure)
    k = KubeClient(manager_settings)
    now = datetime.now(UTC)
    ended = (now - timedelta(seconds=5)).isoformat()
    pod = {
        "metadata": {
            "name": "golden-random",
            "uid": "pod-uid",
            "resourceVersion": "7",
            "ownerReferences": [{"kind": "Job", "uid": "job-uid", "controller": True}],
        },
        "spec": {
            "nodeName": "sandbox-node",
            "volumes": [{"persistentVolumeClaim": {"claimName": manager_settings.golden_name}}],
        },
        "status": {
            "phase": "Succeeded",
            "conditions": [{"type": "PodReadyToStartContainers", "status": "False"}],
            "containerStatuses": [{"state": {"terminated": {"exitCode": 0, "finishedAt": ended}}}],
        },
    }
    k.core = Mock()
    k.storage = Mock()
    k.batch = Mock()
    k.batch.create_namespaced_job.return_value = {}
    k.batch.delete_namespaced_job.return_value = {}
    k.core.create_namespaced_persistent_volume_claim.return_value = {}
    k.core.delete_namespaced_persistent_volume_claim.return_value = {}
    k.core.delete_namespaced_pod.return_value = {}
    k.core.list_namespaced_pod.return_value = {"items": [pod], "metadata": {}}
    k.core.read_persistent_volume.return_value = {
        "spec": {
            "claimRef": {
                "uid": "pvc-uid",
                "name": manager_settings.golden_name,
                "namespace": manager_settings.namespace,
            },
            "csi": {"driver": "example.csi.test", "volumeHandle": "disk-1"},
        }
    }
    k.core.read_node.return_value = {
        "status": {
            "conditions": [
                {"type": "Ready", "status": "True", "lastHeartbeatTime": now.isoformat()}
            ],
            "volumesInUse": [],
            "volumesAttached": [],
        }
    }
    k.storage.list_volume_attachment.return_value = {"items": [], "metadata": {}}
    k.batch.read_namespaced_job.return_value = golden_job(manager_settings)
    yield k
    k.api_client.close()


def pair(settings):
    job, pvc = golden_job(settings), golden_pvc(settings, "job-uid")
    job["metadata"].update(uid="job-uid", resourceVersion="1")
    pvc["metadata"].update(uid="pvc-uid", resourceVersion="1")
    pvc["spec"]["volumeName"] = "pv-1"
    pvc["status"] = {"phase": "Bound"}
    return job, pvc


@pytest.mark.parametrize(
    "blocked",
    [None, "running", "foreign", "replacement", "complete", "used", "unfenced", "not-deleting"],
)
async def test_failed_bake_pod_cleanup_is_release_and_identity_fenced(
    api, manager_settings, blocked
):
    job, pvc = pair(manager_settings)
    job["status"] = {"conditions": [{"type": "Failed", "status": "True"}]}
    pvc["metadata"]["deletionTimestamp"] = "now"
    api.batch.read_namespaced_job.return_value = deepcopy(job)
    api.core.read_namespaced_persistent_volume_claim.return_value = deepcopy(pvc)
    pod = api.core.list_namespaced_pod.return_value["items"][0]
    if blocked == "running":
        pod["status"]["phase"] = "Running"
    elif blocked == "foreign":
        pod["metadata"]["ownerReferences"][0]["uid"] = "other-job"
    elif blocked == "replacement":
        api.core.read_namespaced_persistent_volume_claim.return_value["metadata"]["uid"] = "new"
    elif blocked == "complete":
        api.batch.read_namespaced_job.return_value["status"]["conditions"][0]["type"] = "Complete"
    elif blocked == "used":
        api.core.read_node.return_value["status"]["volumesInUse"] = [
            "kubernetes.io/csi/example.csi.test^disk-1"
        ]
    elif blocked == "unfenced":
        del pod["metadata"]["resourceVersion"]
    elif blocked == "not-deleting":
        del api.core.read_namespaced_persistent_volume_claim.return_value["metadata"][
            "deletionTimestamp"
        ]
    await api.delete_released_bake_pods(pvc, job)
    if blocked:
        api.core.delete_namespaced_pod.assert_not_called()
    else:
        call = api.core.delete_namespaced_pod.call_args
        assert call.args == ("golden-random", manager_settings.namespace)
        assert call.kwargs["body"]["preconditions"] == {"uid": "pod-uid", "resourceVersion": "7"}
        assert "gracePeriodSeconds" not in call.kwargs["body"]
    api.batch.delete_namespaced_job.assert_not_called()
    api.core.delete_namespaced_persistent_volume_claim.assert_not_called()


async def test_live_adapter_bound_and_released_including_attachless_driver(api, manager_settings):
    job, pvc = pair(manager_settings)
    assert await api.released(pvc, job)
    api.core.list_namespaced_pod.assert_called_once_with(
        manager_settings.namespace, limit=200, _continue="", _request_timeout=0.1
    )
    api.core.read_node.assert_called_once_with("sandbox-node", _request_timeout=0.1)
    assert api.storage.list_volume_attachment.called


@pytest.mark.parametrize(
    "phase,expected", [("Failed", True), ("Pending", False), ("Running", False)]
)
async def test_never_bound_claim_cleanup_after_prescheduling_failure(
    api, manager_settings, phase, expected
):
    job, pvc = pair(manager_settings)
    del pvc["spec"]["volumeName"]
    pvc["status"]["phase"] = "Pending"
    pod = api.core.list_namespaced_pod.return_value["items"][0]
    del pod["spec"]["nodeName"]
    pod["status"] = {"phase": phase}
    assert await api.released(pvc, None) is expected
    assert not await api.released(pvc, job)  # Never a ready clone source.
    api.core.read_node.assert_not_called()
    api.core.read_persistent_volume.assert_not_called()
    pod["metadata"]["deletionTimestamp"] = "now"
    assert not await api.released(pvc, None)


@pytest.mark.parametrize("phase", ["Pending", "Running", "Unknown", None])
async def test_any_consumer_blocks_even_without_manager_labels(api, manager_settings, phase):
    job, pvc = pair(manager_settings)
    other = deepcopy(api.core.list_namespaced_pod.return_value["items"][0])
    other["metadata"] = {"name": "foreign-consumer"}
    other["status"]["phase"] = phase
    api.core.list_namespaced_pod.return_value["items"].append(other)
    assert not await api.released(pvc, job)


@pytest.mark.parametrize("state", ["True", "Unknown", None])
async def test_terminal_pod_without_positive_sandbox_teardown_blocks(api, manager_settings, state):
    job, pvc = pair(manager_settings)
    pod = api.core.list_namespaced_pod.return_value["items"][0]
    pod["status"]["conditions"][0]["status"] = state
    assert not await api.released(pvc, job)


async def test_terminating_and_missing_bake_pod_are_not_proof(api, manager_settings):
    job, pvc = pair(manager_settings)
    api.core.list_namespaced_pod.return_value["items"][0]["metadata"]["deletionTimestamp"] = "now"
    assert not await api.released(pvc, job)
    api.core.list_namespaced_pod.return_value["items"] = []
    assert not await api.released(pvc, job)


@pytest.mark.parametrize(
    "field,value",
    [
        ("volumesInUse", ["kubernetes.io/csi/example.csi.test^disk-1"]),
        ("volumesAttached", [{"name": "kubernetes.io/csi/example.csi.test^disk-1"}]),
    ],
)
async def test_volume_use_fails_closed(api, manager_settings, field, value):
    job, pvc = pair(manager_settings)
    api.core.read_node.return_value["status"][field] = value
    assert not await api.released(pvc, job)


@pytest.mark.parametrize(
    "conditions",
    [
        [],
        [{"type": "Ready", "status": "False"}],
        [{"type": "Ready", "status": "Unknown"}],
        [{"type": "Ready", "status": "True"}],
        [{"type": "Ready", "status": "True", "lastHeartbeatTime": "2000-01-01T00:00:00Z"}],
        [{"type": "Ready", "status": "True", "lastHeartbeatTime": "2999-01-01T00:00:00Z"}],
        [{"type": "Ready", "status": "True", "lastHeartbeatTime": "invalid"}],
    ],
)
async def test_node_health_does_not_gate_golden_release(api, manager_settings, conditions):
    job, pvc = pair(manager_settings)
    api.core.read_node.return_value["status"]["conditions"] = conditions
    assert await api.released(pvc, job)
    api.core.list_namespaced_pod.return_value["items"][0]["status"]["conditions"] = []
    assert not await api.released(pvc, job)  # Runtime-sandbox evidence still required.


@pytest.mark.parametrize("state", [True, False, None])
async def test_attachment_is_blocking_even_deleting_or_attached_false(api, manager_settings, state):
    job, pvc = pair(manager_settings)
    api.storage.list_volume_attachment.return_value["items"] = [
        {
            "metadata": {"deletionTimestamp": "now"},
            "spec": {"source": {"persistentVolumeName": "pv-1"}},
            "status": {"attached": state},
        }
    ]
    assert not await api.released(pvc, job)


async def test_pv_claim_uid_mismatch_fails_closed(api, manager_settings):
    job, pvc = pair(manager_settings)
    api.core.read_persistent_volume.return_value["spec"]["claimRef"]["uid"] = "replacement"
    assert not await api.released(pvc, job)


async def test_paginated_pods_and_attachments_do_not_hide_consumers(api, manager_settings):
    job, pvc = pair(manager_settings)
    first = deepcopy(api.core.list_namespaced_pod.return_value)
    first["metadata"]["continue"] = "page-2"
    foreign = deepcopy(first["items"][0])
    foreign["status"]["phase"] = "Running"
    api.core.list_namespaced_pod.side_effect = [first, {"items": [foreign], "metadata": {}}]
    assert not await api.released(pvc, job)
    assert api.core.list_namespaced_pod.call_args.kwargs["_continue"] == "page-2"
    api.core.list_namespaced_pod.side_effect = None
    api.core.list_namespaced_pod.return_value = {"items": first["items"], "metadata": {}}
    api.storage.list_volume_attachment.side_effect = [
        {"items": [], "metadata": {"continue": "page-2"}},
        {"items": [{"spec": {"source": {"persistentVolumeName": "pv-1"}}}], "metadata": {}},
    ]
    assert not await api.released(pvc, job)


@pytest.mark.parametrize("code", [401, 403, 500])
async def test_permission_and_api_failures_are_not_empty_success(api, manager_settings, code):
    job, pvc = pair(manager_settings)
    api.core.list_namespaced_pod.side_effect = ApiException(status=code)
    with pytest.raises(ApiException) as error:
        await api.released(pvc, job)
    assert error.value.status == code


async def test_exact_name_reads_and_uid_resource_version_delete_fencing(api, manager_settings):
    job, pvc = pair(manager_settings)
    api.batch.read_namespaced_job.return_value = job
    api.core.read_namespaced_persistent_volume_claim.return_value = pvc
    assert await api.job() == job
    assert await api.pvc() == pvc
    await api.delete_job(job)
    await api.delete_pvc(pvc)
    for call, uid in (
        (api.batch.delete_namespaced_job.call_args, "job-uid"),
        (api.core.delete_namespaced_persistent_volume_claim.call_args, "pvc-uid"),
    ):
        assert call.args == (manager_settings.golden_name, manager_settings.namespace)
        assert call.kwargs["body"]["preconditions"] == {"uid": uid, "resourceVersion": "1"}
        assert call.kwargs["body"]["propagationPolicy"] == "Foreground"
        assert "gracePeriodSeconds" not in call.kwargs["body"]
    api.batch.read_namespaced_job.side_effect = ApiException(status=404)
    assert await api.job() is None
    api.batch.read_namespaced_job.side_effect = ApiException(status=403)
    with pytest.raises(ApiException):
        await api.job()


async def test_sdk_roundtrip_generated_manifests(api, manager_settings):
    job, pvc = pair(manager_settings)
    for document, model in ((job, "V1Job"), (pvc, "V1PersistentVolumeClaim")):
        import json

        response = Mock(data=json.dumps(document))
        parsed = api.api_client.deserialize(response, model)
        assert isinstance(parsed, (client.V1Job, client.V1PersistentVolumeClaim))
    await api.create_job(job)
    await api.create_pvc(pvc)
    assert api.batch.create_namespaced_job.call_args.args == (manager_settings.namespace, job)
    assert api.core.create_namespaced_persistent_volume_claim.call_args.args == (
        manager_settings.namespace,
        pvc,
    )
