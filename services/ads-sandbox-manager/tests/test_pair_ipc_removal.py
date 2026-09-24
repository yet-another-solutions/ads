from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.pair_ipc_inputs import ipc_identity
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_objects import PairBinding
from test_kube_release import api  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
def ipc_removal(api):  # noqa: F811
    pair = PairBinding(uuid4(), uuid4(), uuid4(), uuid4())
    body = ipc_identity(api.settings, pair, "pod")
    body["metadata"].update(uid=str(uuid4()), resourceVersion="42")
    body["spec"] = {"nodeName": "application"}
    api.core.read_namespaced_pod.side_effect = lambda *a, **kw: deepcopy(body)
    api.core.delete_namespaced_pod.return_value = {}
    return PairControlAdapter(api), pair, body


async def test_original_ipc_placement_includes_rv_and_uses_two_reads(ipc_removal):
    adapter, pair, body = ipc_removal
    uid = body["metadata"]["uid"]
    assert await adapter.ipc_placement(pair, uid) == {
        "uid": uid,
        "node": "application",
        "resource_version": "42",
    }
    assert adapter.kube.core.read_namespaced_pod.call_count == 2
    adapter.kube.core.delete_namespaced_pod.assert_not_called()


@pytest.mark.parametrize("read", [0, 1])
@pytest.mark.parametrize("fault", ["absent", "uid", "node", "owner", "generation", "rv"])
async def test_ipc_capture_rejects_missing_replaced_or_changing_identity(ipc_removal, read, fault):
    adapter, pair, body = ipc_removal
    broken = deepcopy(body)
    if fault == "absent":
        broken = ApiException(status=404)
    elif fault == "node":
        broken["spec"]["nodeName"] = None if read == 0 else "other"
    elif fault == "owner":
        broken["metadata"]["ownerReferences"] = [{"uid": str(uuid4())}]
    elif fault == "generation":
        broken["metadata"]["labels"]["ads.io/attachment-generation"] = str(uuid4())
    elif fault == "rv":
        broken["metadata"]["resourceVersion"] = None if read == 0 else "43"
    else:
        broken["metadata"]["uid"] = str(uuid4())
    reads = [body, body]
    reads[read] = broken
    adapter.kube.core.read_namespaced_pod.side_effect = reads
    with pytest.raises(RuntimeError):
        await adapter.ipc_placement(pair, body["metadata"]["uid"])
    adapter.kube.core.delete_namespaced_pod.assert_not_called()


async def test_ipc_delete_is_uid_rv_fenced_with_normal_grace(ipc_removal):
    adapter, pair, body = ipc_removal
    uid = body["metadata"]["uid"]
    adapter.kube.core.read_namespaced_pod.side_effect = [body, ApiException(status=404)]
    assert await adapter.delete_ipc(pair, uid, node="application")
    call = adapter.kube.core.delete_namespaced_pod.call_args
    assert call.args == (body["metadata"]["name"], adapter.namespace)
    assert call.kwargs["body"] == {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "propagationPolicy": "Foreground",
        "preconditions": {"uid": uid, "resourceVersion": "42"},
    }


@pytest.mark.parametrize("fault", ["uid", "node", "owner", "generation"])
async def test_ipc_delete_never_follows_replacement(ipc_removal, fault):
    adapter, pair, body = ipc_removal
    uid = body["metadata"]["uid"]
    if fault == "node":
        body["spec"]["nodeName"] = "private-worker"
    elif fault == "owner":
        body["metadata"]["ownerReferences"] = [{"uid": str(uuid4())}]
    elif fault == "generation":
        body["metadata"]["labels"]["ads.io/attachment-generation"] = str(uuid4())
    else:
        body["metadata"]["uid"] = str(uuid4())
    with pytest.raises(RuntimeError):
        await adapter.delete_ipc(pair, uid, node="application")
    adapter.kube.core.delete_namespaced_pod.assert_not_called()


@pytest.mark.parametrize("status,absent", [(404, True), (409, False)])
async def test_ipc_delete_reconciles_lost_response_without_force(ipc_removal, status, absent):
    adapter, pair, body = ipc_removal
    adapter.kube.core.read_namespaced_pod.side_effect = [body, ApiException(status=404)]
    adapter.kube.core.delete_namespaced_pod.side_effect = ApiException(status=status)
    assert await adapter.delete_ipc(pair, body["metadata"]["uid"], node="application") is absent


async def test_ipc_absence_does_not_issue_a_new_delete(ipc_removal):
    adapter, pair, body = ipc_removal
    adapter.kube.core.read_namespaced_pod.side_effect = ApiException(status=404)
    assert await adapter.delete_ipc(pair, body["metadata"]["uid"], node="application")
    adapter.kube.core.delete_namespaced_pod.assert_not_called()
