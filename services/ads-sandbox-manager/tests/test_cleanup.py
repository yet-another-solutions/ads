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
    pod["spec"]["volumes"] = [{"persistentVolumeClaim": {"claimName": name}}]
    return CleanupAdapter(api), target("PersistentVolumeClaim", name, uid)


def release(api):
    api.core.list_namespaced_pod.return_value["items"] = []


async def test_capture_stores_exact_pv_identity(api, cleanup):
    adapter, original = cleanup
    captured = await adapter.capture(original)
    assert captured["captured"] is True
    assert captured["pv_name"] == "pv-1" and captured["pv_uid"] == "pv-uid"
    assert captured["volume_key"] == "kubernetes.io/csi/example.csi.test^disk-1"
    assert "nodes" not in captured and "delete_policy" not in captured
    assert "reclaim_guard" not in captured
    # A live terminal Pod is unfinished runtime evidence and blocks release.
    assert not await adapter.released(captured)
    release(api)
    assert await adapter.released(captured)
    assert not await adapter.reclaimed(captured)  # PVC disappearance alone is not reclamation.
    api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    assert not await adapter.reclaimed(captured)
    api.core.read_persistent_volume.side_effect = ApiException(status=404)
    assert await adapter.reclaimed(captured)


async def test_release_demands_stored_pv_identity_and_fails_closed(api, cleanup):
    adapter, original = cleanup
    captured = await adapter.capture(original)
    release(api)
    for field in ("pv_name", "pv_uid"):
        broken = {**captured, field: None}
        assert not await adapter.released(broken)
    bare = dict(original)
    assert not await adapter.released(bare)
    assert not await adapter.reclaimed(bare)


async def test_missing_or_replaced_claim_capture_stays_bare(api, cleanup):
    adapter, original = cleanup
    api.core.read_namespaced_persistent_volume_claim.return_value["metadata"]["uid"] = "replaced"
    captured = await adapter.capture(original)
    assert not captured.get("captured") and "pv_name" not in captured
    assert not await adapter.released(captured)
    api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    captured = await adapter.capture(original)
    assert not captured.get("captured")


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
    api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    api.core.read_persistent_volume.return_value["metadata"]["uid"] = "replacement"
    assert not await adapter.reclaimed(captured)
    api.core.read_namespaced_persistent_volume_claim.side_effect = None
    pvc = api.core.read_namespaced_persistent_volume_claim.return_value
    pvc["spec"] = {}
    pvc["status"] = {"phase": "Pending"}
    never_bound = await adapter.capture(original)
    assert never_bound["captured"] and never_bound.get("never_bound")
    release(api)  # The planted consumer pod must be gone before release.
    assert await adapter.released(never_bound)
    api.core.read_namespaced_persistent_volume_claim.side_effect = ApiException(status=404)
    assert await adapter.reclaimed(never_bound)


async def test_volume_attachment_blocks_release_without_node_reads(api, cleanup):
    adapter, original = cleanup
    captured = await adapter.capture(original)
    release(api)
    api.storage.list_volume_attachment.return_value["items"] = [
        {"spec": {"source": {"persistentVolumeName": "pv-1"}}}
    ]
    assert not await adapter.released(captured)
    api.core.read_node.assert_not_called()


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
