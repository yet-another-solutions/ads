# ruff: noqa: F811
from copy import deepcopy
from unittest.mock import Mock

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.cleanup import CleanupAdapter
from ads_sandbox_manager.lifecycle_store import target
from test_kube_release import api  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
def cleanup(api):
    api.apps = Mock()
    name, uid = "ads-sandbox-disk", "pvc-uid"
    pvc = {
        "metadata": {"name": name, "uid": uid, "resourceVersion": "7"},
        "spec": {"volumeName": "pv-1"},
        "status": {"phase": "Bound"},
    }
    api.core.read_namespaced_persistent_volume_claim.return_value = pvc
    api.core.read_persistent_volume.return_value["metadata"] = {
        "uid": "pv-uid",
        "finalizers": ["external-provisioner.volume.kubernetes.io/finalizer"],
    }
    spec = api.core.read_persistent_volume.return_value["spec"]
    spec["claimRef"]["name"] = name
    spec["persistentVolumeReclaimPolicy"] = "Delete"
    pod = api.core.list_namespaced_pod.return_value["items"][0]
    pod["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] = name
    return CleanupAdapter(api), target("PersistentVolumeClaim", name, uid)


def release(api):
    api.core.list_namespaced_pod.return_value["items"] = []


async def test_capture_persistable_positive_release_and_reclaim_contract(api, cleanup):
    adapter, original = cleanup
    captured = await adapter.capture(original)
    assert captured["pv_uid"] == "pv-uid" and captured["nodes"] == ["sandbox-node"]
    assert captured["reclaim_guard"] and captured["delete_policy"]
    assert not await adapter.released(captured)  # Even a terminal Pod still exists.
    release(api)
    assert await adapter.released(captured)
    assert not await adapter.reclaimed(captured)
    api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    assert not await adapter.reclaimed(captured)  # PVC disappearance alone is not reclamation.
    api.core.read_persistent_volume.side_effect = ApiException(status=404)
    assert await adapter.reclaimed(captured)


@pytest.mark.parametrize("csi", [False, True])
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
async def test_node_health_does_not_gate_resource_release(api, cleanup, csi, conditions):
    adapter, original = cleanup
    if not csi:
        del api.core.read_persistent_volume.return_value["spec"]["csi"]
    captured = await adapter.capture(original)
    api.core.read_node.return_value["status"]["conditions"] = conditions
    # A live consumer still blocks, regardless of Node health.
    assert not await adapter.released(captured)
    release(api)
    # No later Ready heartbeat is needed, including for persisted old targets.
    assert await adapter.released(captured)
    if csi:
        api.core.read_node.return_value["status"]["volumesInUse"] = [captured["volume_key"]]
        assert not await adapter.released(captured)


@pytest.mark.parametrize(
    "broken",
    ["inuse", "attached", "attachment", "missing-nodes", "not-captured"],
)
async def test_release_fails_closed_for_incomplete_or_negative_evidence(api, cleanup, broken):
    adapter, original = cleanup
    captured = await adapter.capture(original)
    release(api)
    status = api.core.read_node.return_value["status"]
    if broken == "inuse":
        status["volumesInUse"] = [captured["volume_key"]]
    elif broken == "attached":
        status["volumesAttached"] = [{"name": captured["volume_key"]}]
    elif broken == "attachment":
        api.storage.list_volume_attachment.return_value["items"] = [
            {
                "spec": {"source": {"persistentVolumeName": "pv-1"}},
                "status": {"attached": False},
            }
        ]
    elif broken == "missing-nodes":
        captured["nodes"] = []
    else:
        captured["captured"] = False
    assert not await adapter.released(captured)


@pytest.mark.parametrize("missing", ["reclaim_guard", "delete_policy"])
async def test_reclaim_requires_controller_backing_storage_contract(api, cleanup, missing):
    adapter, original = cleanup
    captured = await adapter.capture(original)
    captured[missing] = False
    release(api)
    api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    api.core.read_persistent_volume.side_effect = ApiException(status=404)
    assert not await adapter.reclaimed(captured)


async def test_exact_delete_uid_and_resource_version_preconditions(api, cleanup):
    adapter, original = cleanup
    captured = await adapter.capture(original)
    api.core.delete_namespaced_persistent_volume_claim.return_value = {}
    await adapter.delete(captured)
    call = api.core.delete_namespaced_persistent_volume_claim.call_args
    assert call.kwargs["body"]["preconditions"] == {"uid": "pvc-uid", "resourceVersion": "7"}
    assert call.kwargs["body"]["propagationPolicy"] == "Foreground"
    api.core.read_namespaced_persistent_volume_claim.return_value["metadata"]["uid"] = "replacement"
    await adapter.delete(captured)
    assert api.core.delete_namespaced_persistent_volume_claim.call_count == 1
    api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    assert not (await adapter.capture(original)).get("captured")
    assert not await adapter.reclaimed(original)


async def test_binding_race_and_foreign_claim_fail_closed(api, cleanup):
    adapter, original = cleanup
    api.core.read_persistent_volume.return_value["spec"]["claimRef"]["uid"] = "foreign"
    with pytest.raises(RuntimeError, match="identity"):
        await adapter.capture(original)
    api.core.read_persistent_volume.return_value["spec"]["claimRef"]["uid"] = original["uid"]
    captured = await adapter.capture(original)
    api.core.read_namespaced_persistent_volume_claim.return_value["spec"]["volumeName"] = "other"
    with pytest.raises(RuntimeError, match="binding"):
        await adapter.delete(captured)
    assert not await adapter.released(captured)
    api.core.delete_namespaced_persistent_volume_claim.assert_not_called()


async def test_never_bound_release_and_replacement_pv_are_distinct(api, cleanup):
    adapter, original = cleanup
    captured = await adapter.capture(original)
    release(api)
    api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    api.core.read_persistent_volume.return_value["metadata"]["uid"] = "replacement"
    assert not await adapter.reclaimed(captured)
    api.core.read_namespaced_persistent_volume_claim.side_effect = None
    pvc = api.core.read_namespaced_persistent_volume_claim.return_value
    pvc["spec"] = {}
    pvc["status"] = {"phase": "Pending"}
    never_bound = await adapter.capture(original)
    assert await adapter.released(never_bound)
    api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    assert await adapter.reclaimed(never_bound)


async def test_inventory_filters_unrelated_and_golden_objects(api, cleanup):
    adapter, _ = cleanup
    from ads_sandbox_manager.objects import COMPONENT
    from ads_sandbox_manager.session_objects import SANDBOX, SESSION

    owned = {"metadata": {"labels": {COMPONENT: "ads-sandbox", SESSION: "s", SANDBOX: "b"}}}
    golden = deepcopy(owned)
    golden["metadata"]["labels"][COMPONENT] = "ads-sandbox-golden"
    api.apps.list_namespaced_deployment.return_value = {"items": [owned, golden], "metadata": {}}
    api.core.list_namespaced_persistent_volume_claim.return_value = {"items": [{}], "metadata": {}}
    assert await adapter.inventory() == [{**owned, "kind": "Deployment"}]
