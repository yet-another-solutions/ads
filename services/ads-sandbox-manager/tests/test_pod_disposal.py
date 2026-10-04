from __future__ import annotations

from copy import deepcopy
from unittest.mock import Mock

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.cleanup import CleanupAdapter
from test_kube_release import api  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
def pod_adapter(api):
    pod = {
        "metadata": {"name": "ads-sandbox-ipc-x", "uid": "ipc-uid", "resourceVersion": "11"},
        "spec": {"nodeName": "sandbox-node"},
    }
    api.core.read_namespaced_pod.return_value = pod
    api.core.list_namespaced_pod.return_value = {"items": [pod], "metadata": {}}
    return CleanupAdapter(api), deepcopy(pod)


async def test_pod_delete_fenced_observation_and_preconditions(api, pod_adapter):
    adapter, pod = pod_adapter
    reads = iter([deepcopy(pod), None])

    def read_pod(name, *args, **kwargs):
        observed = next(reads)
        if observed is None:
            raise ApiException(status=404)
        return observed

    api.core.read_namespaced_pod = Mock(side_effect=read_pod)
    assert await adapter.delete_pod(pod, "ipc-uid", node="sandbox-node")
    call = api.core.delete_namespaced_pod.call_args
    assert call.args == ("ads-sandbox-ipc-x", adapter.kube.settings.namespace)
    assert call.kwargs["body"]["preconditions"] == {"uid": "ipc-uid", "resourceVersion": "11"}
    assert call.kwargs["body"]["propagationPolicy"] == "Foreground"


async def test_pod_delete_404_is_released_and_409_is_retry(api, pod_adapter):
    adapter, pod = pod_adapter

    def conflict(*args, **kwargs):
        raise ApiException(status=409)

    api.core.delete_namespaced_pod.side_effect = conflict
    assert not await adapter.delete_pod(pod, "ipc-uid", node="sandbox-node")
    api.core.delete_namespaced_pod.side_effect = None
    api.core.delete_namespaced_pod.return_value = {}

    def gone(*args, **kwargs):
        raise ApiException(status=404)

    api.core.delete_namespaced_pod.side_effect = gone
    assert await adapter.delete_pod(pod, "ipc-uid", node="sandbox-node")


async def test_pod_delete_replacement_or_node_move_refuses(api, pod_adapter):
    adapter, pod = pod_adapter
    replaced = deepcopy(pod)
    replaced["metadata"]["uid"] = "other-uid"
    api.core.read_namespaced_pod.return_value = replaced
    with pytest.raises(RuntimeError, match="cleanup Pod was replaced"):
        await adapter.delete_pod(pod, "ipc-uid", node="sandbox-node")
    moved = deepcopy(pod)
    moved["spec"]["nodeName"] = "elsewhere"
    api.core.read_namespaced_pod.return_value = moved
    with pytest.raises(RuntimeError, match="cleanup Pod moved away from captured node"):
        await adapter.delete_pod(pod, "ipc-uid", node="sandbox-node")
