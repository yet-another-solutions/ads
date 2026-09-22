# ruff: noqa: F811
from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from ads_sandbox_manager.pair_objects import (
    GENERATION,
    PairBinding,
    control_ingress,
    control_service,
    ipc_pair_environment,
    pair_name,
    pair_selector,
    placement,
    pod_group,
    resources,
)
from test_session_objects import object_settings  # noqa: F401


@pytest.fixture
def pair():
    return PairBinding(uuid4(), uuid4(), uuid4(), uuid4())


def test_two_native_groups_bind_each_vm_only_to_its_own_local_relay(object_settings, pair):
    groups = [pod_group(object_settings, pair, side) for side in ("guest", "egress")]
    assert len({g["metadata"]["name"] for g in groups}) == 2
    for group in groups:
        assert group["apiVersion"] == "scheduling.k8s.io/v1alpha2"
        assert group["spec"] == {
            "schedulingPolicy": {"gang": {"minCount": 2}},
            "schedulingConstraints": {"topology": [{"key": "kubernetes.io/hostname"}]},
        }
        assert "ownerReferences" not in group["metadata"]
    for side in ("guest", "egress"):
        assert placement(pair, side) == placement(pair, side + "-relay")
        assert placement(pair, side) == {"schedulingGroup": {"podGroupName": pair_name(pair, side)}}
    assert placement(pair, "guest") != placement(pair, "egress")
    with pytest.raises(ValueError):
        placement(pair, "ipc")


def test_control_services_use_exact_generation_and_do_not_wait_for_peer(object_settings, pair):
    for role in ("egress", "guest-relay", "egress-relay"):
        service = control_service(object_settings, pair, role)
        spec = service["spec"]
        assert spec["type"] == "ClusterIP"
        assert spec["selector"] == pair_selector(pair, role)
        assert spec["selector"][GENERATION] == str(pair.generation)
        assert "externalIPs" not in spec and "loadBalancerIP" not in spec
        assert spec["publishNotReadyAddresses"] is False
        assert len(spec["ports"]) == (2 if role == "egress-relay" else 1)
        if role == "egress-relay":
            assert spec["ports"][1]["protocol"] == "UDP"
        replacement = replace(pair, generation=uuid4())
        assert pair_selector(replacement, role) != spec["selector"]
        assert pair_name(replacement, role) == service["metadata"]["name"]


def test_control_is_pair_and_role_bound_not_project_identity_only(object_settings, pair):
    other_pair = replace(pair, sandbox_id=uuid4())
    old_pair = replace(pair, generation=uuid4())
    for role in ("egress", "guest-relay", "egress-relay"):
        policy = control_ingress(object_settings, pair, role)
        spec = policy["spec"]
        assert spec["policyTypes"] == ["Ingress"]
        assert spec["podSelector"]["matchLabels"] == pair_selector(pair, role)
        allowed = spec["ingress"][0]["from"]
        assert allowed == [{"podSelector": {"matchLabels": pair_selector(pair, "ipc")}}]
        for forbidden in (
            pair_selector(pair, "guest"),
            pair_selector(other_pair, "ipc"),
            pair_selector(old_pair, "ipc"),
        ):
            assert forbidden != allowed[0]["podSelector"]["matchLabels"]
        if role.endswith("-relay"):
            peer = "guest-relay" if role == "egress-relay" else "egress-relay"
            assert spec["ingress"][1]["from"] == [
                {"podSelector": {"matchLabels": pair_selector(pair, peer)}}
            ]
            assert spec["ingress"][1]["ports"][0]["protocol"] == "UDP"
        else:
            assert len(spec["ingress"]) == 1
        assert "namespaceSelector" not in str(spec) and "ipBlock" not in str(spec)


def test_ipc_uses_three_distinct_direct_health_targets(object_settings, pair):
    env = ipc_pair_environment(object_settings, pair)
    assert env["ADS_SANDBOX_IPC_PROJECT_ID"] == str(pair.project_id)
    urls = [v for k, v in env.items() if k.endswith("URL")]
    assert len(set(urls)) == 3
    assert all(url.startswith("https://") for url in urls)
    assert all(f".{object_settings.namespace}.svc:" in url for url in urls)
    assert env["ADS_SANDBOX_IPC_LOCAL_RELAY_HEALTH_URL"].endswith("/health")
    assert env["ADS_SANDBOX_IPC_PEER_RELAY_HEALTH_URL"].endswith("/health")


def test_resources_contain_no_secrets_workloads_or_readiness_substitutes(object_settings, pair):
    objects = resources(object_settings, pair)
    assert [o["kind"] for o in objects] == [
        "PodGroup",
        "PodGroup",
        "NetworkPolicy",
        "NetworkPolicy",
        "NetworkPolicy",
        "Service",
        "Service",
        "Service",
    ]
    assert len({(o["kind"], o["metadata"]["name"]) for o in objects}) == len(objects)
    assert all(o["metadata"]["namespace"] == object_settings.namespace for o in objects)
    assert "token" not in str(objects).lower()
    assert "secret" not in str(objects).lower()


@pytest.mark.parametrize("role", ["ipc", "guest", "foreign"])
def test_invalid_control_roles_rejected(object_settings, pair, role):
    with pytest.raises(ValueError):
        control_service(object_settings, pair, role)
    with pytest.raises(ValueError):
        control_ingress(object_settings, pair, role)


def test_untrusted_non_uuid_pair_identity_rejected(pair):
    with pytest.raises(ValueError):
        replace(pair, project_id="model-supplied")
