from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.ca import CaEnsure
from ads_sandbox_manager.ca_objects import CA_FORMAT, CA_NAME, ca_job, ca_pvc
from ads_sandbox_manager.config import CaSettings
from ads_sandbox_manager.objects import JOB_UID

pytestmark = pytest.mark.anyio


class CaKube:
    def __init__(self):
        self.objects = {}
        self.calls = []
        self.released_names = set()
        self.release_hook = None

    async def named_job(self, name):
        return deepcopy(self.objects.get(name))

    named_pvc = named_job

    async def create_job(self, body):
        name = body["metadata"]["name"]
        if name in self.objects:
            raise ApiException(status=409)
        self.objects[name] = deepcopy(body)
        self.objects[name]["metadata"].update(uid=str(uuid4()), resourceVersion="1")
        self.calls.append(("create", name))

    create_pvc = create_job

    async def delete_job(self, obj):
        name = obj["metadata"]["name"]
        current = self.objects[name]
        if any(
            current["metadata"][key] != obj["metadata"][key] for key in ("uid", "resourceVersion")
        ):
            raise ApiException(status=409)
        current["metadata"]["deletionTimestamp"] = "now"
        self.calls.append(("delete", name))

    delete_pvc = delete_job

    async def released(self, pvc, job):
        if self.release_hook:
            self.release_hook()
        return pvc["metadata"]["name"] in self.released_names

    async def delete_released_ca_pods(self, job, claims):
        self.calls.append(("cleanup", CA_NAME))

    def finish(self, status="Complete"):
        self.objects[CA_NAME]["status"] = {"conditions": [{"type": status, "status": "True"}]}
        for role in ("public", "private"):
            obj = self.objects.get(f"{CA_NAME}-{role}")
            if obj:
                obj["status"] = {"phase": "Bound"}

    def release(self):
        self.released_names = {f"{CA_NAME}-{role}" for role in ("public", "private")}


@pytest.fixture
def ca_settings(manager_settings):
    return replace(
        manager_settings,
        ca=CaSettings("registry.test/ca:0.0.1", "configured-signer", "configured-extra"),
    )


@pytest.fixture
async def prepared(ca_settings):
    kube = CaKube()
    ensure = CaEnsure(ca_settings, kube)
    for _ in range(3):
        assert not await ensure.poll()
    kube.calls.clear()
    return ensure, kube


async def test_job_first_two_output_repair_release_and_restart(ca_settings):
    kube = CaKube()
    ensure = CaEnsure(ca_settings, kube)
    assert not await ensure.poll()
    assert kube.calls == [("create", CA_NAME)]
    # Simulate another replica resuming after the first died before either claim.
    ensure = CaEnsure(ca_settings, kube)
    assert not await ensure.poll()
    assert kube.calls[-1] == ("create", f"{CA_NAME}-public")
    assert not await ensure.poll()
    assert kube.calls[-1] == ("create", f"{CA_NAME}-private")
    assert not await ensure.poll()
    kube.finish()
    assert not await ensure.poll()
    kube.released_names.add(f"{CA_NAME}-public")
    assert not await ensure.poll()  # Half-released is not ready.
    kube.release()
    sources = await ensure.clone_sources()
    assert set(sources) == {"public", "private"}
    assert all(
        pvc["metadata"]["labels"][JOB_UID] == kube.objects[CA_NAME]["metadata"]["uid"]
        for pvc in sources.values()
    )
    assert await CaEnsure(ca_settings, kube).poll()
    changed = replace(
        ca_settings, golden_version="v0.0.999", ca=replace(ca_settings.ca, image="new")
    )
    assert await CaEnsure(changed, kube).poll()  # No implicit per-release/input rotation.
    kube.released_names.clear()
    assert not await ensure.poll()


@pytest.mark.parametrize("condition", ["Failed", "Complete"])
@pytest.mark.parametrize("missing", ["public", "private"])
async def test_partial_pair_keeps_job_lock_until_both_outputs_disappear(
    prepared, condition, missing
):
    ensure, kube = prepared
    kube.finish(condition)
    del kube.objects[f"{CA_NAME}-{missing}"]
    survivor = "private" if missing == "public" else "public"
    assert not await ensure.poll()
    assert kube.calls == []
    kube.release()
    assert not await ensure.poll()
    assert kube.calls == [("delete", f"{CA_NAME}-{survivor}"), ("cleanup", CA_NAME)]
    assert not await ensure.poll()
    assert ("delete", CA_NAME) not in kube.calls
    del kube.objects[f"{CA_NAME}-{survivor}"]
    assert not await ensure.poll()
    assert kube.calls[-1] == ("delete", CA_NAME)
    assert not await ensure.poll()
    del kube.objects[CA_NAME]
    assert not await ensure.poll()
    assert kube.calls[-1] == ("create", CA_NAME)


async def test_failed_pair_needs_joint_release_before_any_deletion(prepared):
    ensure, kube = prepared
    kube.finish("Failed")
    kube.released_names.add(f"{CA_NAME}-public")
    assert not await ensure.poll()
    assert kube.calls == []
    kube.release()
    assert not await ensure.poll()
    assert kube.calls == [
        ("delete", f"{CA_NAME}-public"),
        ("delete", f"{CA_NAME}-private"),
        ("cleanup", CA_NAME),
    ]


async def test_deleting_complete_output_invalidates_and_cleans_whole_pair(prepared):
    ensure, kube = prepared
    kube.finish()
    kube.release()
    kube.objects[f"{CA_NAME}-public"]["metadata"]["deletionTimestamp"] = "now"
    assert not await ensure.poll()
    assert kube.calls == [("delete", f"{CA_NAME}-private"), ("cleanup", CA_NAME)]


async def test_deleting_pending_output_is_not_repaired_or_adopted(prepared):
    ensure, kube = prepared
    kube.objects[f"{CA_NAME}-public"]["metadata"]["deletionTimestamp"] = "now"
    del kube.objects[f"{CA_NAME}-private"]
    assert not await ensure.poll()
    assert kube.calls == []


async def test_orphan_pair_never_promoted_and_no_new_job_until_both_gone(prepared):
    ensure, kube = prepared
    kube.finish()
    del kube.objects[CA_NAME]
    assert not await ensure.poll()
    assert kube.calls == []
    kube.release()
    assert not await ensure.poll()
    assert kube.calls == [("delete", f"{CA_NAME}-public"), ("delete", f"{CA_NAME}-private")]


@pytest.mark.parametrize("name", [CA_NAME, f"{CA_NAME}-public", f"{CA_NAME}-private"])
async def test_foreign_object_blocks_all_mutation(prepared, name):
    ensure, kube = prepared
    kube.objects[name]["metadata"]["labels"][CA_FORMAT] = "foreign"
    kube.finish("Failed")
    kube.release()
    with pytest.raises(RuntimeError, match="foreign"):
        await ensure.poll()
    assert kube.calls == []


@pytest.mark.parametrize("role", ["public", "private"])
async def test_attempt_mismatch_blocks_pair(prepared, role):
    ensure, kube = prepared
    kube.objects[f"{CA_NAME}-{role}"]["metadata"]["labels"][JOB_UID] = "replacement-job"
    kube.finish("Failed")
    kube.release()
    with pytest.raises(RuntimeError, match="different"):
        await ensure.poll()
    assert kube.calls == []


async def test_source_with_disposable_owner_is_not_adopted_or_deleted(prepared):
    ensure, kube = prepared
    kube.objects[f"{CA_NAME}-private"]["metadata"]["ownerReferences"] = [
        {"kind": "Job", "uid": kube.objects[CA_NAME]["metadata"]["uid"], "controller": True}
    ]
    kube.finish("Failed")
    kube.release()
    with pytest.raises(RuntimeError, match="incompatible"):
        await ensure.poll()
    assert kube.calls == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("volumeMode", "Filesystem"),
        ("storageClassName", "other"),
        ("dataSource", {"kind": "PersistentVolumeClaim", "name": "other"}),
        ("dataSourceRef", {"kind": "PersistentVolumeClaim", "name": "other"}),
        ("resources", {"requests": {"storage": "512Mi"}}),
        ("accessModes", ["ReadWriteMany"]),
    ],
)
async def test_incompatible_output_not_adopted(prepared, field, value):
    ensure, kube = prepared
    kube.objects[f"{CA_NAME}-private"]["spec"][field] = value
    with pytest.raises(RuntimeError, match="incompatible"):
        await ensure.poll()


@pytest.mark.parametrize("name", [CA_NAME, f"{CA_NAME}-public", f"{CA_NAME}-private"])
async def test_release_proof_rechecks_all_resource_versions(prepared, name):
    ensure, kube = prepared
    kube.finish()
    kube.release()
    kube.release_hook = lambda: kube.objects[name]["metadata"].update(resourceVersion="2")
    assert not await ensure.poll()
    assert kube.calls == []


@pytest.mark.parametrize("counter", ["active", "terminating"])
async def test_complete_job_with_live_work_is_not_ready(prepared, counter):
    ensure, kube = prepared
    kube.finish()
    kube.release()
    kube.objects[CA_NAME]["status"][counter] = 1
    assert not await ensure.poll()


async def test_two_replicas_race_on_job_name_not_output_creation(ca_settings):
    kube = CaKube()
    original = kube.named_job
    barrier = asyncio.Barrier(2)

    async def race(name):
        result = await original(name)
        await barrier.wait()
        return result

    kube.named_job = race
    a, b = CaEnsure(ca_settings, kube), CaEnsure(ca_settings, kube)
    results = await asyncio.gather(a.poll(), b.poll(), return_exceptions=True)
    assert sum(isinstance(result, ApiException) and result.status == 409 for result in results) == 1
    assert kube.calls == [("create", CA_NAME)]


async def test_normal_runtime_job_is_offline_and_secrets_never_guest_outputs(ca_settings):
    job = ca_job(ca_settings)
    pod = job["spec"]["template"]["spec"]
    assert "runtimeClassName" not in pod
    assert pod["automountServiceAccountToken"] is False
    assert pod["enableServiceLinks"] is False
    assert job["spec"]["backoffLimit"] == 0 and "ttlSecondsAfterFinished" not in job["spec"]
    container = pod["containers"][0]
    assert container["securityContext"]["privileged"] is False
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"], "add": ["SYS_ADMIN"]}
    assert container["securityContext"]["appArmorProfile"] == {"type": "Unconfined"}
    assert container["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert not any(v.get("hostPath") for v in pod["volumes"])
    assert not any(pod.get(field) for field in ("hostNetwork", "hostPID", "hostIPC"))
    assert container["env"][0]["valueFrom"]["fieldRef"]["fieldPath"].endswith(
        "['batch.kubernetes.io/controller-uid']"
    )
    assert {d["devicePath"] for d in container["volumeDevices"]} == {
        "/dev/ads-ca-public",
        "/dev/ads-ca-private",
    }
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert volumes["signer"]["secret"]["secretName"] == "configured-signer"
    assert volumes["additional"]["configMap"]["name"] == "configured-extra"
    assert all(
        m["readOnly"] for m in container["volumeMounts"] if m["name"] in ("signer", "additional")
    )
    for role in ("public", "private"):
        pvc = ca_pvc(ca_settings, role, "attempt")
        assert "ownerReferences" not in pvc["metadata"]
        assert pvc["spec"]["volumeMode"] == "Block"
        assert pvc["metadata"]["labels"][JOB_UID] == "attempt"
