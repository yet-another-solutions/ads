# ruff: noqa: F811
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.egress_compute_inputs import egress_manifest, egress_payload
from ads_sandbox_manager.pair_compute_inputs import compute_manifest
from ads_sandbox_manager.pair_compute_kube import PairComputeAdapter
from ads_sandbox_manager.pair_objects import GENERATION
from ads_sandbox_manager.pair_store import CONTROL_RESOURCES, resource_key
from test_egress_compute import object_settings, runtime, state  # noqa: F401
from test_pair_compute_mount_defaults import desired  # noqa: F401
from test_pair_objects import pair  # noqa: F401
from test_session_kube import session_api  # noqa: F401
from test_session_objects import object_settings as base_settings  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
def admitted(desired):
    observed = deepcopy(desired)
    observed["spec"]["overhead"] = {"memory": "160Mi"}
    runtime = {
        "metadata": {"name": desired["spec"]["runtimeClassName"], "uid": "runtime-uid"},
        "overhead": {"podFixed": {"memory": "160Mi"}},
    }
    kube = Mock()
    kube.runtime_class = AsyncMock(return_value=runtime)
    return PairComputeAdapter(kube, Mock()), observed, runtime


async def test_exact_admission_overhead_keeps_payload_and_container_budget(desired, admitted):
    adapter, observed, runtime = admitted
    before = deepcopy((desired, observed, runtime))
    assert not adapter._spec_matches(observed, desired)
    assert await adapter._admitted_spec_matches(observed, desired)
    adapter.kube.runtime_class.assert_awaited_once_with(desired["spec"]["runtimeClassName"])
    assert (desired, observed, runtime) == before


async def test_no_overhead_needs_no_new_api_read(desired, admitted):
    adapter, _, _ = admitted
    assert await adapter._admitted_spec_matches(deepcopy(desired), desired)
    adapter.kube.runtime_class.assert_not_awaited()


@pytest.mark.parametrize(
    "change",
    ["absent", "name", "uid", "deleting", "no-overhead", "empty", "memory", "extra-cpu"],
)
async def test_missing_or_changed_runtime_class_is_fail_closed(desired, admitted, change):
    adapter, observed, runtime = admitted
    if change == "absent":
        adapter.kube.runtime_class.return_value = None
    elif change in ("name", "uid"):
        runtime["metadata"][change] = ""
    elif change == "deleting":
        runtime["metadata"]["deletionTimestamp"] = "now"
    elif change == "no-overhead":
        del runtime["overhead"]
    elif change == "empty":
        runtime["overhead"]["podFixed"] = {}
    elif change == "memory":
        runtime["overhead"]["podFixed"]["memory"] = "161Mi"
    else:
        runtime["overhead"]["podFixed"]["cpu"] = "250m"
    assert not await adapter._admitted_spec_matches(observed, desired)


@pytest.mark.parametrize("overhead", [None, {}, {"memory": "1Gi"}, {"cpu": "250m"}])
async def test_untrusted_pod_overhead_is_not_stripped(desired, admitted, overhead):
    adapter, observed, _ = admitted
    observed["spec"]["overhead"] = overhead
    assert not await adapter._admitted_spec_matches(observed, desired)


@pytest.mark.parametrize("name", [None, "", "foreign-runtime"])
async def test_pod_cannot_select_another_runtime_class(desired, admitted, name):
    adapter, observed, _ = admitted
    observed["spec"]["runtimeClassName"] = name
    assert not await adapter._admitted_spec_matches(observed, desired)
    adapter.kube.runtime_class.assert_not_awaited()


async def test_overhead_requires_committed_runtime_class(desired, admitted):
    adapter, observed, _ = admitted
    del desired["spec"]["runtimeClassName"]
    assert not await adapter._admitted_spec_matches(observed, desired)
    adapter.kube.runtime_class.assert_not_awaited()


@pytest.mark.parametrize("change", ["budget", "capabilities", "volume", "host-network", "extra"])
async def test_overhead_does_not_relax_other_pod_assertions(desired, admitted, change):
    adapter, observed, _ = admitted
    spec = observed["spec"]
    container = spec["containers"][0]
    if change == "budget":
        container["resources"]["limits"]["memory"] = "2Gi"
    elif change == "capabilities":
        container["securityContext"]["capabilities"]["add"].append("CHOWN")
    elif change == "volume":
        container["volumeMounts"][0]["readOnly"] = True
    elif change == "host-network":
        spec["hostNetwork"] = True
    else:
        spec["unrecognizedAuthority"] = True
    assert not await adapter._admitted_spec_matches(observed, desired)


async def test_runtime_read_failure_propagates_without_retry(desired, admitted):
    adapter, observed, _ = admitted
    adapter.kube.runtime_class.side_effect = ApiException(status=403)
    with pytest.raises(ApiException) as error:
        await adapter._admitted_spec_matches(observed, desired)
    assert error.value.status == 403
    adapter.kube.runtime_class.assert_awaited_once()


async def test_runtime_class_get_uses_verified_client_deadline_and_no_namespace(session_api):
    session_api.node = Mock()
    session_api.node.read_runtime_class.return_value = {"metadata": {"name": "kata-egress"}}
    assert await session_api.runtime_class("kata-egress") == {"metadata": {"name": "kata-egress"}}
    session_api.node.read_runtime_class.assert_called_once_with("kata-egress", _request_timeout=0.1)
    assert session_api.node.mock_calls == [
        call.read_runtime_class("kata-egress", _request_timeout=0.1)
    ]


@pytest.mark.parametrize("status", [404, 403, 409, 500])
async def test_runtime_class_only_404_is_absent(session_api, status):
    session_api.node = Mock()
    session_api.node.read_runtime_class.side_effect = ApiException(status=status)
    if status == 404:
        assert await session_api.runtime_class("kata-egress") is None
    else:
        with pytest.raises(ApiException) as error:
            await session_api.runtime_class("kata-egress")
        assert error.value.status == status
    session_api.node.read_runtime_class.assert_called_once()


@pytest.mark.parametrize(
    "change", [None, "uid", "generation", "annotations", "deleting", "budget", "overhead"]
)
async def test_observe_keeps_identity_and_custody_checks_with_overhead(
    object_settings, pair, state, runtime, change
):
    row = SimpleNamespace(
        ca_attempt=uuid4(),
        ca_clones={name: str(uuid4()) for name in ("guest", "egress", "key")},
        ca_sources={name: str(uuid4()) for name in ("public", "private")},
        golden_version=object_settings.golden_version,
    )
    payload = egress_payload(row, state, runtime)
    controls = {resource_key(*item): str(uuid4()) for item in CONTROL_RESOURCES}
    payload.update(manifest=egress_manifest(object_settings, pair, payload), control_uids=controls)
    desired = compute_manifest(object_settings, pair, "egress", payload)
    observed = deepcopy(desired)
    observed["metadata"].update(uid="owned-pod", resourceVersion="1")
    observed["spec"]["overhead"] = {"memory": "160Mi"}
    kube = Mock(settings=object_settings)
    kube._get = AsyncMock(return_value=observed)
    kube.runtime_class = AsyncMock(
        return_value={
            "metadata": {"name": runtime.runtime_class, "uid": "runtime-uid"},
            "overhead": {"podFixed": {"memory": "160Mi"}},
        }
    )
    adapter = PairComputeAdapter(kube, Mock())
    adapter._dependencies = AsyncMock()
    if change == "uid":
        observed["metadata"]["uid"] = "replacement"
    elif change == "generation":
        observed["metadata"]["labels"][GENERATION] = str(uuid4())
    elif change == "annotations":
        observed["metadata"]["annotations"] = {"unexpected": "true"}
    elif change == "deleting":
        observed["metadata"]["deletionTimestamp"] = "now"
    elif change == "budget":
        observed["spec"]["containers"][0]["resources"]["limits"]["memory"] = "2Gi"
    elif change == "overhead":
        observed["spec"]["overhead"]["memory"] = "1Gi"
    if change is not None:
        with pytest.raises(RuntimeError):
            await adapter.observe(pair, "egress", payload, controls, "owned-pod")
        adapter._dependencies.assert_awaited_once_with(pair, "egress", payload, controls)
    else:
        assert await adapter.observe(pair, "egress", payload, controls, "owned-pod") == "owned-pod"
        assert adapter._dependencies.await_args_list == [
            call(pair, "egress", payload, controls),
            call(pair, "egress", payload, controls),
        ]
    assert "overhead" not in payload["manifest"]["spec"]
