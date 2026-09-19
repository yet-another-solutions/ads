from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.golden import GoldenEnsure
from ads_sandbox_manager.objects import JOB_UID, VERSION, golden_job, golden_pvc

pytestmark = pytest.mark.anyio


async def test_create_bake_release_restart_and_loss_of_release(manager):
    g, k = manager.golden, manager.kube
    assert not await g.poll()
    assert k.calls == [("create", "job")]
    assert not await g.poll()
    assert k.calls == [("create", "job"), ("create", "pvc")]
    assert not await g.poll()  # Pending is in progress, not a failed bake.
    k.finish()
    assert not await g.poll()  # Succeeded + Bound does not mean released.
    k.is_released = True
    assert await g.poll()
    restarted = GoldenEnsure(manager.settings, k)
    assert await restarted.poll()
    k.is_released = False
    assert not await restarted.poll()
    assert k.calls == [("create", "job"), ("create", "pvc")]


async def test_failed_bake_keeps_name_lock_until_partial_pvc_is_gone(baked):
    g, k = baked.golden, baked.kube
    k.finish("Failed")
    assert not await g.poll()
    assert not k.calls  # Still in use: do not delete.
    k.is_released = True
    assert not await g.poll()
    assert k.calls == [("delete", "pvc")]
    assert k.bake_pods_deleted
    assert not await g.poll()
    assert k.calls == [("delete", "pvc")]  # Wait for asynchronous PVC deletion.
    k.objects["pvc"] = None
    assert not await g.poll()
    assert k.calls[-1] == ("delete", "job")
    assert not await g.poll()
    k.objects["job"] = None
    assert not await g.poll()
    assert not await g.poll()
    assert k.calls[-2:] == [("create", "job"), ("create", "pvc")]
    k.finish()
    assert await g.poll()


async def test_deleting_failed_claim_recovers_retained_pod_cleanup(baked):
    k = baked.kube
    k.finish("Failed")
    k.objects["pvc"]["metadata"]["deletionTimestamp"] = "now"
    k.is_released = True
    assert not await baked.golden.poll()
    assert k.bake_pods_deleted
    assert not k.calls  # Job remains the lock; PVC deletion is already in progress.


@pytest.mark.parametrize("terminal", ["Failed", "Complete"])
async def test_finished_job_with_missing_claim_is_recreated(baked, terminal):
    baked.kube.finish(terminal)
    baked.kube.objects["pvc"] = None
    assert not await baked.golden.poll()
    assert baked.kube.calls == [("delete", "job")]


async def test_orphan_claim_is_not_promoted_and_is_deleted_before_new_job(baked):
    k = baked.kube
    k.objects["job"] = None
    assert not await baked.golden.poll()
    assert not k.calls
    k.is_released = True
    assert not await baked.golden.poll()
    assert k.calls == [("delete", "pvc")]
    k.objects["pvc"] = None
    assert not await baked.golden.poll()
    assert k.calls[-1] == ("create", "job")


@pytest.mark.parametrize("kind", ["job", "pvc"])
async def test_foreign_same_name_objects_are_never_adopted_or_deleted(baked, kind):
    baked.kube.objects[kind]["metadata"]["labels"][VERSION] = "v0.0.9"
    with pytest.raises(RuntimeError, match="foreign"):
        await baked.golden.poll()
    assert not baked.kube.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("volumeMode", "Filesystem"),
        ("storageClassName", "wrong"),
        ("accessModes", ["ReadWriteMany"]),
        ("resources", {"requests": {"storage": "21Gi"}}),
        ("dataSource", {"kind": "PersistentVolumeClaim", "name": "another"}),
    ],
)
async def test_incompatible_claim_is_never_attached_or_deleted(baked, field, value):
    baked.kube.objects["pvc"]["spec"][field] = value
    with pytest.raises(RuntimeError, match="incompatible"):
        await baked.golden.poll()
    assert not baked.kube.calls


async def test_failed_job_cannot_delete_claim_from_new_attempt(baked):
    baked.kube.finish("Failed")
    baked.kube.objects["pvc"]["metadata"]["labels"][JOB_UID] = "other-uid"
    baked.kube.is_released = True
    with pytest.raises(RuntimeError, match="different bake"):
        await baked.golden.poll()
    assert not baked.kube.calls


@pytest.mark.parametrize("phase", ["Pending", "Lost", None])
async def test_clone_source_must_still_be_bound(baked, phase):
    baked.kube.is_released = True
    baked.kube.objects["pvc"]["status"]["phase"] = phase
    assert not await baked.golden.poll()


@pytest.mark.parametrize("counter", ["active", "terminating"])
async def test_complete_job_with_remaining_work_is_not_ready(baked, counter):
    baked.kube.is_released = True
    baked.kube.objects["job"]["status"][counter] = 1
    assert not await baked.golden.poll()


@pytest.mark.parametrize(
    "kind,field",
    [("job", "uid"), ("pvc", "uid"), ("job", "resourceVersion"), ("pvc", "resourceVersion")],
)
async def test_readiness_rechecks_both_object_generations(baked, kind, field):
    baked.kube.is_released = True

    def race():
        baked.kube.objects[kind]["metadata"][field] = "replacement"

    baked.kube.release_hook = race
    assert not await baked.golden.poll()


async def test_two_replicas_only_one_job_and_claim_and_loser_repairs_winner_crash(manager):
    k = manager.kube
    original_read = k.job
    barrier = asyncio.Barrier(2)

    async def racing_read():
        result = await original_read()
        await barrier.wait()
        return result

    k.job = racing_read
    a, b = manager.golden, GoldenEnsure(manager.settings, k)
    results = await asyncio.gather(a.poll(), b.poll(), return_exceptions=True)
    assert sum(isinstance(r, ApiException) and r.status == 409 for r in results) == 1
    assert k.calls == [("create", "job")]
    k.job = original_read
    assert not await b.poll()
    assert k.calls == [("create", "job"), ("create", "pvc")]


async def test_stale_delete_precondition_does_not_remove_replacement(baked):
    k = baked.kube
    old = await k.pvc()
    replacement = deepcopy(k.objects["pvc"])
    replacement["metadata"]["uid"] = "new-uid"
    k.objects["pvc"] = replacement
    with pytest.raises(ApiException) as error:
        await k.delete_pvc(old)
    assert error.value.status == 409
    assert "deletionTimestamp" not in replacement["metadata"]


async def test_job_and_pvc_contract(manager_settings):
    s = replace(
        manager_settings,
        session_size="30Gi",
        golden_slack="3Gi",
        node_selector={"ads.io/role": "sandbox"},
        tolerations=[{"key": "ads.io/sandbox", "operator": "Exists", "effect": "NoSchedule"}],
        image_pull_secrets=("registry-pull",),
        resources={"requests": {"cpu": "1"}},
    )
    job, pvc = golden_job(s), golden_pvc(s, "job-uid")
    assert job["metadata"]["name"] == pvc["metadata"]["name"] == "ads-sandbox-golden-v0-0-10"
    assert job["metadata"]["labels"][VERSION] == "v0.0.10"
    assert job["spec"]["backoffLimit"] == 0
    assert job["spec"]["parallelism"] == job["spec"]["completions"] == 1
    assert job["spec"]["activeDeadlineSeconds"] == s.bake_seconds
    assert "ttlSecondsAfterFinished" not in job["spec"]
    template = job["spec"]["template"]
    assert "annotations" not in template["metadata"]
    pod = template["spec"]
    assert pod["runtimeClassName"] == "kata-qemu"
    assert pod["nodeSelector"] == s.node_selector
    assert pod["tolerations"] == s.tolerations
    assert pod["dnsPolicy"] == "None"
    assert not pod["automountServiceAccountToken"]
    assert not pod["enableServiceLinks"]
    assert pod["imagePullSecrets"] == [{"name": "registry-pull"}]
    (container,) = pod["containers"]
    assert container["image"] == s.golden_image
    assert "command" not in container and "args" not in container
    assert container["env"] == [
        {"name": "ADS_SESSION_DEVICE", "value": "/dev/ads-session"},
        {"name": "ADS_SESSION_SIZE", "value": "30Gi"},
    ]
    assert container["securityContext"]["privileged"] is False
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"]["add"] == ["SYS_ADMIN"]
    assert container["volumeDevices"] == [{"name": "session", "devicePath": "/dev/ads-session"}]
    assert pvc["spec"]["resources"]["requests"]["storage"] == str(33 * 1024**3)
    assert pvc["spec"]["volumeMode"] == "Block"
    assert pvc["spec"]["storageClassName"] == "sandbox-block"
    assert "ownerReferences" not in pvc["metadata"]
    assert "volumeBindingMode" not in pvc["spec"]  # Belongs to the StorageClass, not PVC.
