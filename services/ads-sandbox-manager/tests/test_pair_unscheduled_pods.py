from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.pair_ipc_inputs import ipc_identity
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES, PairBinding, compute_identity
from test_kube_release import api  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture(params=[*COMPUTE_ROLES, "ipc"])
def unscheduled(api, request):  # noqa: F811
    role = request.param
    pair = PairBinding(uuid4(), uuid4(), uuid4(), uuid4())
    body = (
        ipc_identity(api.settings, pair, "pod")
        if role == "ipc"
        else compute_identity(api.settings, pair, role)
    )
    body["metadata"].update(uid=str(uuid4()), resourceVersion="41")
    body["spec"] = {}
    body["status"] = {"phase": "Pending"}
    api.core.read_namespaced_pod.side_effect = lambda *a, **kw: deepcopy(body)
    api.core.delete_namespaced_pod.side_effect = lambda *a, **kw: deepcopy(body)
    return PairControlAdapter(api), pair, role, body


async def observe(f):
    adapter, pair, role, body = f
    return await adapter.unscheduled_pod(pair, role, body["metadata"]["uid"])


async def test_unscheduled_capture_is_not_release_until_conditional_delete_receipt(unscheduled):
    adapter, pair, role, body = unscheduled
    captured = await observe(unscheduled)
    assert captured == {
        "uid": body["metadata"]["uid"],
        "resource_version": "41",
        "node": "",
        "deletion_timestamp": None,
    }
    adapter.kube.core.delete_namespaced_pod.assert_not_called()
    body["metadata"].update(resourceVersion="42", deletionTimestamp="2026-09-24T12:00:00Z")
    response = await adapter.delete_unscheduled(pair, role, captured)
    assert response == {
        **captured,
        "resource_version": "42",
        "deletion_timestamp": "2026-09-24T12:00:00Z",
    }
    call = adapter.kube.core.delete_namespaced_pod.call_args
    assert call.args == (body["metadata"]["name"], adapter.namespace)
    assert call.kwargs["body"] == {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "propagationPolicy": "Foreground",
        "preconditions": {"uid": captured["uid"], "resourceVersion": "41"},
    }
    assert adapter.kube.core.read_namespaced_pod.call_count == 1  # No absence inference.


async def test_scheduled_pending_pod_never_qualifies_as_never_started(unscheduled):
    adapter, _, _, body = unscheduled
    body["spec"]["nodeName"] = "worker"
    assert await observe(unscheduled) is None
    adapter.kube.core.delete_namespaced_pod.assert_not_called()


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "owner",
        "generation",
        "node-type",
        "phase",
        "container",
        "init",
        "ephemeral",
        "condition",
        "timestamp",
        "spec",
        "rv",
    ],
)
async def test_unscheduled_capture_rejects_missing_or_contradictory_evidence(unscheduled, fault):
    adapter, pair, role, body = unscheduled
    uid = body["metadata"]["uid"]
    if fault == "missing":
        adapter.kube.core.read_namespaced_pod.side_effect = ApiException(status=404)
    elif fault == "owner":
        body["metadata"]["ownerReferences"] = [{"uid": str(uuid4())}]
    elif fault == "generation":
        body["metadata"]["labels"]["ads.io/attachment-generation"] = str(uuid4())
    elif fault == "node-type":
        body["spec"]["nodeName"] = None
    elif fault == "phase":
        body["status"]["phase"] = "Succeeded"
    elif fault in ("container", "init", "ephemeral"):
        key = {
            "container": "containerStatuses",
            "init": "initContainerStatuses",
            "ephemeral": "ephemeralContainerStatuses",
        }[fault]
        body["status"][key] = [{"state": {"terminated": {}}}]
    elif fault == "condition":
        body["status"]["conditions"] = [{"type": "PodScheduled", "status": "True"}]
    elif fault == "timestamp":
        body["metadata"]["deletionTimestamp"] = "2026-09-24"
    elif fault == "spec":
        del body["spec"]
    else:
        body["metadata"]["resourceVersion"] = ""
    with pytest.raises(RuntimeError):
        await adapter.unscheduled_pod(pair, role, uid)
    adapter.kube.core.delete_namespaced_pod.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 404, 409, 500])
async def test_delete_errors_never_become_positive_evidence(unscheduled, status):
    adapter, pair, role, _ = unscheduled
    captured = await observe(unscheduled)
    adapter.kube.core.delete_namespaced_pod.side_effect = ApiException(status=status)
    with pytest.raises(ApiException) as error:
        await adapter.delete_unscheduled(pair, role, captured)
    assert error.value.status == status
    assert adapter.kube.core.delete_namespaced_pod.call_count == 1
    assert adapter.kube.core.read_namespaced_pod.call_count == 1


async def test_lost_delete_response_and_later_404_remain_unresolved(unscheduled):
    adapter, pair, role, body = unscheduled
    captured = await observe(unscheduled)
    adapter.kube.core.delete_namespaced_pod.side_effect = TimeoutError("lost response")
    with pytest.raises(TimeoutError):
        await adapter.delete_unscheduled(pair, role, captured)
    adapter.kube.core.read_namespaced_pod.side_effect = ApiException(status=404)
    with pytest.raises(RuntimeError, match="not never-scheduled"):
        await adapter.unscheduled_pod(pair, role, body["metadata"]["uid"])
    assert adapter.kube.core.delete_namespaced_pod.call_count == 1


@pytest.mark.parametrize("fault", ["node", "uid", "body", "owner", "rv"])
async def test_delete_response_must_prove_the_original_unscheduled_pod(unscheduled, fault):
    adapter, pair, role, body = unscheduled
    captured = await observe(unscheduled)
    if fault == "node":
        body["spec"]["nodeName"] = "worker"
    elif fault == "uid":
        body["metadata"]["uid"] = str(uuid4())
    elif fault == "body":
        adapter.kube.core.delete_namespaced_pod.side_effect = None
        adapter.kube.core.delete_namespaced_pod.return_value = {}
    elif fault == "owner":
        body["metadata"]["ownerReferences"] = [{"uid": str(uuid4())}]
    else:
        del body["metadata"]["resourceVersion"]
    with pytest.raises(RuntimeError):
        await adapter.delete_unscheduled(pair, role, captured)


async def test_deleting_unscheduled_observation_is_positive_without_another_delete(unscheduled):
    adapter, _, _, body = unscheduled
    body["metadata"]["deletionTimestamp"] = "2026-09-24T12:00:00Z"
    captured = await observe(unscheduled)
    assert captured["node"] == "" and captured["deletion_timestamp"] is not None
    adapter.kube.core.delete_namespaced_pod.assert_not_called()
