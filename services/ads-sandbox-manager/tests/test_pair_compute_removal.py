# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES, PairBinding, compute_identity
from test_kube_release import api  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
def removal(api):
    adapter = PairControlAdapter(api)
    pair = PairBinding(uuid4(), uuid4(), uuid4(), uuid4())
    bodies = {}
    for role in COMPUTE_ROLES:
        body = compute_identity(api.settings, pair, role)
        body["metadata"].update(uid=str(uuid4()), resourceVersion="17")
        body["spec"] = {"nodeName": "worker"}
        bodies[role] = body
    uids = {f"Pod/{role}": body["metadata"]["uid"] for role, body in bodies.items()}
    by_name = {body["metadata"]["name"]: body for body in bodies.values()}
    api.core.read_namespaced_pod.side_effect = lambda name, *a, **kw: deepcopy(by_name[name])
    api.core.delete_namespaced_pod.return_value = {}
    return adapter, pair, bodies, uids


async def test_placement_requires_two_complete_identity_reads_not_readiness(removal):
    adapter, pair, bodies, uids = removal
    for body in bodies.values():
        body["status"] = {"phase": "Failed"}
        body["metadata"]["deletionTimestamp"] = "now"
    assert await adapter.compute_node(pair, uids) == "worker"
    read = adapter.kube.core.read_namespaced_pod
    names = [bodies[role]["metadata"]["name"] for role in COMPUTE_ROLES]
    assert [call.args for call in read.call_args_list] == [
        (name, adapter.namespace) for name in names * 2
    ]
    assert {call[0] for call in adapter.kube.core.mock_calls} == {"read_namespaced_pod"}


async def test_placement_pins_input_identities_before_the_first_read(removal):
    adapter, pair, bodies, uids = removal
    read = adapter.kube.core.read_namespaced_pod
    original = read.side_effect
    count = 0

    def changed(name, *args, **kwargs):
        nonlocal count
        count += 1
        if count == 2:
            uids["Pod/guest"] = str(uuid4())
            bodies["guest"]["metadata"]["uid"] = uids["Pod/guest"]
        return original(name, *args, **kwargs)

    read.side_effect = changed
    with pytest.raises(RuntimeError, match="replaced"):
        await adapter.compute_node(pair, uids)
    adapter.kube.core.delete_namespaced_pod.assert_not_called()


@pytest.mark.parametrize("fault", ["missing", "extra", "none", "blank", "duplicate", "type"])
async def test_invalid_placement_scope_fails_before_reads(removal, fault):
    adapter, pair, _, uids = removal
    if fault == "missing":
        del uids["Pod/guest"]
    elif fault == "extra":
        uids["Pod/ipc"] = str(uuid4())
    else:
        uids["Pod/guest"] = {
            "none": None,
            "blank": " ",
            "duplicate": uids["Pod/egress"],
            "type": 3,
        }[fault]
    with pytest.raises(ValueError):
        await adapter.compute_node(pair, uids)
    assert not adapter.kube.core.mock_calls


@pytest.mark.parametrize("scan", [0, 1])
@pytest.mark.parametrize(
    "fault", ["absent", "uid", "generation", "owner", "unassigned", "other_node", "malformed_node"]
)
async def test_placement_rejects_missing_replaced_or_split_pair_on_either_read(
    removal, scan, fault
):
    adapter, pair, bodies, uids = removal
    reads = [deepcopy(bodies[role]) for role in COMPUTE_ROLES] * 2
    index = scan * 4 + 2
    broken = deepcopy(reads[index])
    if fault == "absent":
        reads[index] = ApiException(status=404)
    else:
        if fault == "uid":
            broken["metadata"]["uid"] = str(uuid4())
        elif fault == "generation":
            broken["metadata"]["labels"]["ads.io/attachment-generation"] = str(uuid4())
        elif fault == "owner":
            broken["metadata"]["ownerReferences"] = [{"uid": "controller"}]
        else:
            broken["spec"]["nodeName"] = {
                "unassigned": None,
                "other_node": "other",
                "malformed_node": False,
            }[fault]
        reads[index] = broken
    adapter.kube.core.read_namespaced_pod.side_effect = reads
    with pytest.raises(RuntimeError):
        await adapter.compute_node(pair, uids)
    adapter.kube.core.delete_namespaced_pod.assert_not_called()


@pytest.mark.parametrize("role", COMPUTE_ROLES)
async def test_delete_uses_exact_uid_rv_and_default_grace_then_checks_api(removal, role):
    adapter, pair, bodies, uids = removal
    assert not await adapter.delete_compute(pair, role, uids[f"Pod/{role}"], node="worker")
    call = adapter.kube.core.delete_namespaced_pod.call_args
    assert call.args == (bodies[role]["metadata"]["name"], adapter.namespace)
    assert call.kwargs == {
        "body": {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "propagationPolicy": "Foreground",
            "preconditions": {"uid": uids[f"Pod/{role}"], "resourceVersion": "17"},
        },
        "_request_timeout": adapter.kube.settings.control_seconds,
    }
    assert adapter.kube.core.read_namespaced_pod.call_count == 2
    assert {call[0] for call in adapter.kube.core.mock_calls} == {
        "read_namespaced_pod",
        "delete_namespaced_pod",
    }


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize(
    "fault", ["uid", "node", "generation", "owner", "version", "name", "namespace"]
)
async def test_delete_never_follows_a_replaced_or_unfenced_pod(removal, phase, fault):
    adapter, pair, bodies, uids = removal
    original = bodies["guest"]
    altered = deepcopy(original)
    if fault == "node":
        altered["spec"]["nodeName"] = "other"
    elif fault == "generation":
        altered["metadata"]["labels"]["ads.io/attachment-generation"] = str(uuid4())
    elif fault == "owner":
        altered["metadata"]["ownerReferences"] = [{"uid": "controller"}]
    elif fault == "version":
        del altered["metadata"]["resourceVersion"]
    else:
        altered["metadata"][fault] = "replacement"
    read = adapter.kube.core.read_namespaced_pod
    read.side_effect = [altered] if phase == "before" else [original, altered]
    with pytest.raises(RuntimeError):
        await adapter.delete_compute(pair, "guest", uids["Pod/guest"], node="worker")
    assert adapter.kube.core.delete_namespaced_pod.call_count == (phase == "after")


@pytest.mark.parametrize(
    "fault", ["missing_uid", "blank_uid", "missing_node", "blank_node", "role"]
)
async def test_delete_requires_explicit_scope_before_io(removal, fault):
    adapter, pair, _, uids = removal
    uid, node, role = uids["Pod/guest"], "worker", "guest"
    if fault == "role":
        role = "ipc"
    elif fault.endswith("uid"):
        uid = None if fault == "missing_uid" else " "
    else:
        node = None if fault == "missing_node" else " "
    with pytest.raises(ValueError):
        await adapter.delete_compute(pair, role, uid, node=node)
    assert not adapter.kube.core.mock_calls


async def test_terminating_pod_is_observed_without_forcing_deletion(removal):
    adapter, pair, bodies, uids = removal
    body = bodies["guest"]
    body["metadata"]["deletionTimestamp"] = "now"
    assert not await adapter.delete_compute(pair, "guest", uids["Pod/guest"], node="worker")
    adapter.kube.core.read_namespaced_pod.side_effect = [body, ApiException(status=404)]
    assert await adapter.delete_compute(pair, "guest", uids["Pod/guest"], node="worker")
    adapter.kube.core.delete_namespaced_pod.assert_not_called()


@pytest.mark.parametrize("status,absent", [(404, True), (409, False)])
async def test_delete_races_require_post_read_and_never_force_conflicts(removal, status, absent):
    adapter, pair, bodies, uids = removal
    adapter.kube.core.read_namespaced_pod.side_effect = [bodies["guest"], ApiException(status=404)]
    adapter.kube.core.delete_namespaced_pod.side_effect = ApiException(status=status)
    assert await adapter.delete_compute(pair, "guest", uids["Pod/guest"], node="worker") is absent
    assert adapter.kube.core.read_namespaced_pod.call_count == (2 if status == 404 else 1)


async def test_initial_absence_is_api_only_and_does_not_issue_delete(removal):
    adapter, pair, _, uids = removal
    adapter.kube.core.read_namespaced_pod.side_effect = ApiException(status=404)
    assert await adapter.delete_compute(pair, "guest", uids["Pod/guest"], node="worker")
    adapter.kube.core.delete_namespaced_pod.assert_not_called()


@pytest.mark.parametrize("operation", ["placement", "read", "delete", "post_read"])
@pytest.mark.parametrize(
    "error", [ApiException(status=403), ApiException(status=500), TimeoutError()]
)
async def test_unavailable_api_never_reports_absence(removal, operation, error):
    adapter, pair, bodies, uids = removal
    if operation == "delete":
        adapter.kube.core.delete_namespaced_pod.side_effect = error
    else:
        adapter.kube.core.read_namespaced_pod.side_effect = (
            [bodies["guest"], error] if operation == "post_read" else error
        )
    with pytest.raises(type(error)):
        if operation == "placement":
            await adapter.compute_node(pair, uids)
        else:
            await adapter.delete_compute(pair, "guest", uids["Pod/guest"], node="worker")
