# ruff: noqa: F811
from copy import deepcopy
from unittest.mock import Mock
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_objects import GENERATION, PairBinding
from test_kube_release import api  # noqa: F401

pytestmark = pytest.mark.anyio
CASES = [
    ("PodGroup", "guest"),
    ("PodGroup", "egress"),
    ("Service", "egress"),
    ("Service", "guest-relay"),
    ("Service", "egress-relay"),
    ("NetworkPolicy", "egress"),
    ("NetworkPolicy", "guest-relay"),
    ("NetworkPolicy", "egress-relay"),
]


@pytest.fixture
def controls(api):
    adapter = PairControlAdapter(api)
    adapter.custom = Mock()
    adapter.networking = Mock()
    pair = PairBinding(uuid4(), uuid4(), uuid4(), uuid4())
    return adapter, pair


def configure(controls, kind, role):
    adapter, pair = controls
    body = adapter._desired(pair, kind, role)
    observed = deepcopy(body)
    observed["metadata"].update(uid="owned-uid", resourceVersion="7")
    if kind == "Service":
        observed["spec"].update(
            clusterIP="10.2.3.4",
            clusterIPs=["10.2.3.4"],
            ipFamilies=["IPv4"],
            ipFamilyPolicy="SingleStack",
            internalTrafficPolicy="Cluster",
            sessionAffinity="None",
        )
    if kind == "PodGroup":
        sdk, resource, verb = adapter.custom, "custom_object", "get"
    elif kind == "Service":
        sdk, resource, verb = adapter.kube.core, "service", "read"
    else:
        sdk, resource, verb = adapter.networking, "network_policy", "read"
    read = getattr(sdk, verb + "_namespaced_" + resource)
    create = getattr(sdk, "create_namespaced_" + resource)
    delete = getattr(sdk, "delete_namespaced_" + resource)
    read.return_value = observed
    create.return_value = delete.return_value = {}
    return observed, read, create, delete


@pytest.mark.parametrize("kind,role", CASES)
@pytest.mark.parametrize("conflict", [False, True])
async def test_create_then_verify_and_idempotent_exact_uid(controls, kind, role, conflict):
    adapter, pair = controls
    observed, read, create, _ = configure(controls, kind, role)
    read.side_effect = [ApiException(status=404), observed]
    if conflict:
        create.side_effect = ApiException(status=409)
    assert await adapter.ensure(pair, kind, role) == "owned-uid"
    desired = adapter._desired(pair, kind, role)
    assert create.call_args.kwargs["body"] == desired
    assert create.call_args.kwargs["_request_timeout"] == adapter.kube.settings.control_seconds
    if kind == "PodGroup":
        assert create.call_args.args == (
            "scheduling.k8s.io",
            "v1alpha2",
            adapter.kube.settings.namespace,
            "podgroups",
        )
    else:
        assert create.call_args.args == (adapter.kube.settings.namespace,)
    read.side_effect = None
    assert await adapter.ensure(pair, kind, role, "owned-uid") == "owned-uid"
    assert create.call_count == 1


@pytest.mark.parametrize("kind,role", CASES)
async def test_bound_absence_never_recreates(controls, kind, role):
    adapter, pair = controls
    _, read, create, _ = configure(controls, kind, role)
    read.side_effect = ApiException(status=404)
    with pytest.raises(RuntimeError, match="disappeared"):
        await adapter.ensure(pair, kind, role, "old-uid")
    create.assert_not_called()


@pytest.mark.parametrize("kind,role", CASES)
@pytest.mark.parametrize(
    "changed", ["uid", "generation", "namespace", "owner", "version", "deleting"]
)
async def test_foreign_or_unfenced_objects_are_never_adopted(controls, kind, role, changed):
    adapter, pair = controls
    observed, _, create, _ = configure(controls, kind, role)
    meta = observed["metadata"]
    if changed == "generation":
        meta["labels"][GENERATION] = str(uuid4())
    elif changed == "owner":
        meta["ownerReferences"] = [{"uid": "foreign"}]
    elif changed == "version":
        del meta["resourceVersion"]
    elif changed == "deleting":
        meta["deletionTimestamp"] = "now"
    else:
        meta[changed] = "replacement"
    with pytest.raises(RuntimeError):
        await adapter.ensure(pair, kind, role, "owned-uid")
    create.assert_not_called()


@pytest.mark.parametrize("kind,role", CASES)
async def test_policy_and_group_fields_cannot_be_dropped_or_widened(controls, kind, role):
    adapter, pair = controls
    observed, _, _, _ = configure(controls, kind, role)
    observed["spec"]["unexpected"] = {}
    with pytest.raises(RuntimeError, match="incompatible"):
        await adapter.ensure(pair, kind, role)


@pytest.mark.parametrize(
    "field,value",
    [
        ("externalIPs", ["192.0.2.1"]),
        ("externalName", "foreign.test"),
        ("type", "LoadBalancer"),
        ("selector", {}),
        ("ports", []),
        ("clusterIP", "None"),
        ("sessionAffinity", "ClientIP"),
        ("publishNotReadyAddresses", True),
    ],
)
async def test_service_exposure_and_routing_cannot_be_changed(controls, field, value):
    adapter, pair = controls
    observed, _, _, _ = configure(controls, "Service", "egress")
    observed["spec"][field] = value
    with pytest.raises(RuntimeError, match="incompatible"):
        await adapter.ensure(pair, "Service", "egress")


@pytest.mark.parametrize("kind,role", CASES)
async def test_delete_is_uid_rv_fenced_and_requires_observed_absence(controls, kind, role):
    adapter, pair = controls
    observed, read, _, delete = configure(controls, kind, role)
    assert not await adapter.delete(pair, kind, role, "owned-uid")
    options = delete.call_args.kwargs["body"]
    assert options["preconditions"] == {"uid": "owned-uid", "resourceVersion": "7"}
    assert options["propagationPolicy"] == "Foreground"
    assert "gracePeriodSeconds" not in options
    observed["metadata"]["deletionTimestamp"] = "now"
    read.side_effect = [observed, ApiException(status=404)]
    assert await adapter.delete(pair, kind, role, "owned-uid")
    assert delete.call_count == 1


@pytest.mark.parametrize("status,complete", [(404, True), (409, False)])
async def test_delete_races_do_not_claim_unobserved_success(controls, status, complete):
    adapter, pair = controls
    observed, read, _, delete = configure(controls, "Service", "egress")
    delete.side_effect = ApiException(status=status)
    read.side_effect = [observed, ApiException(status=404)]
    assert await adapter.delete(pair, "Service", "egress", "owned-uid") is complete


async def test_delete_never_follows_replacement_or_foreign_generation(controls):
    adapter, pair = controls
    observed, read, _, delete = configure(controls, "PodGroup", "guest")
    replacement = deepcopy(observed)
    replacement["metadata"]["uid"] = "replacement"
    read.side_effect = [observed, replacement]
    with pytest.raises(RuntimeError, match="replaced"):
        await adapter.delete(pair, "PodGroup", "guest", "owned-uid")
    assert delete.call_count == 1
    read.side_effect = None
    observed["metadata"]["labels"][GENERATION] = str(uuid4())
    with pytest.raises(RuntimeError, match="foreign"):
        await adapter.delete(pair, "PodGroup", "guest", "owned-uid")
    assert delete.call_count == 1


async def test_unknown_resource_and_missing_uid_fail_before_api(controls):
    adapter, pair = controls
    with pytest.raises(ValueError):
        await adapter.ensure(pair, "Secret", "egress")
    with pytest.raises(ValueError):
        await adapter.delete(pair, "Service", "egress", "")
    adapter.custom.assert_not_called()
    adapter.networking.assert_not_called()


@pytest.mark.parametrize("status", [401, 403, 500])
async def test_read_errors_are_not_absence(controls, status):
    adapter, pair = controls
    _, read, create, delete = configure(controls, "Service", "egress")
    read.side_effect = ApiException(status=status)
    with pytest.raises(ApiException):
        await adapter.ensure(pair, "Service", "egress")
    with pytest.raises(ApiException):
        await adapter.delete(pair, "Service", "egress", "owned-uid")
    create.assert_not_called()
    delete.assert_not_called()


async def test_lost_create_response_is_not_success_but_retry_can_verify_same_intent(controls):
    adapter, pair = controls
    observed, read, create, _ = configure(controls, "Service", "egress")
    read.side_effect = ApiException(status=404)
    create.side_effect = TimeoutError("lost reply after commit")
    with pytest.raises(TimeoutError):
        await adapter.ensure(pair, "Service", "egress")
    read.side_effect = None
    read.return_value = observed
    assert await adapter.ensure(pair, "Service", "egress") == "owned-uid"
    assert create.call_count == 1


async def test_unobservable_create_and_failed_absence_check_remain_incomplete(controls):
    adapter, pair = controls
    _, read, create, delete = configure(controls, "Service", "egress")
    read.side_effect = ApiException(status=404)
    with pytest.raises(RuntimeError, match="not observable"):
        await adapter.ensure(pair, "Service", "egress")
    assert create.call_count == 1
    observed, read, _, delete = configure(controls, "Service", "egress")
    delete.side_effect = ApiException(status=404)
    read.side_effect = [observed, ApiException(status=403)]
    with pytest.raises(ApiException):
        await adapter.delete(pair, "Service", "egress", "owned-uid")


@pytest.mark.parametrize("kind,role", CASES)
async def test_changed_required_spec_and_api_identity_are_rejected(controls, kind, role):
    adapter, pair = controls
    observed, _, _, _ = configure(controls, kind, role)
    original = deepcopy(observed)
    for key in tuple(adapter._desired(pair, kind, role)["spec"]):
        observed["spec"] = deepcopy(original["spec"])
        del observed["spec"][key]
        with pytest.raises(RuntimeError, match="incompatible"):
            await adapter.ensure(pair, kind, role)
    observed["spec"] = original["spec"]
    observed["apiVersion"] = "foreign/v1"
    with pytest.raises(RuntimeError, match="foreign"):
        await adapter.ensure(pair, kind, role)
