from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from test_reset_preservation import (
    load,
    protected,
    store,  # noqa: F401
)

preferences = load("preferences")
workloads = load("workloads")


def test_fresh_owner_verified_exchange_for_each_supported_api_call(store):  # noqa: F811
    owner, model_id = str(uuid4()), str(uuid4())
    configured = {
        "issuer": "https://identity.invalid/realms/fixture",
        "client_id": "ads",
        "client_secret": "synthetic-client-secret",
        "preferences_url": "https://preferences.invalid",
        "owners": {owner: {"refresh_token": "synthetic-refresh-0"}},
    }
    store.write("owner-auth", configured)
    api = preferences.PreferencesModels(store, None)
    calls, refreshed, wrong = [], 0, False

    def request(method, url, **kwargs):
        nonlocal refreshed
        calls.append((method, url, deepcopy(kwargs)))
        if url.endswith("/token"):
            body = kwargs["data"]
            if body["grant_type"] == "refresh_token":
                assert body["refresh_token"] == "synthetic-refresh-" + str(refreshed)
                refreshed += 1
                result = {
                    "access_token": "synthetic-owner",
                    "refresh_token": "synthetic-refresh-" + str(refreshed),
                }
            else:
                assert body["audience"] == "ads-preferences"
                assert body["subject_token"] == "synthetic-owner"
                result = {"access_token": "synthetic-exchanged"}
        elif url.endswith("/userinfo"):
            assert kwargs["headers"]["Authorization"] == "Bearer synthetic-owner"
            result = {"sub": str(uuid4()) if wrong else owner}
        else:
            assert kwargs["headers"]["Authorization"] == "Bearer synthetic-exchanged"
            result = {"id": model_id}
        return SimpleNamespace(
            content=json.dumps(result).encode(),
            json=lambda: result,
            raise_for_status=lambda: None,
        )

    api.client.request = request
    try:
        assert api.model(owner, model_id) == {"id": model_id}
        assert api.model(owner, model_id) == {"id": model_id}
        assert refreshed == 2 and len(calls) == 8
        assert store.read("owner-auth")["owners"][owner]["refresh_token"] == "synthetic-refresh-2"
        wrong = True
        with pytest.raises(protected.PreservationError):
            api.model(owner, model_id)
        assert len(calls) == 10  # Refresh/userinfo only; wrong subject never reaches preferences.
    finally:
        api.close()


@pytest.mark.parametrize(
    "url",
    [
        "http://preferences.invalid",
        "https://user:secret@preferences.invalid",
        "https://preferences.invalid?token=secret",
        "https://preferences.invalid#token",
    ],
)
def test_reset_api_origins_require_explicit_tls_without_embedded_credentials(url):
    with pytest.raises(protected.PreservationError):
        preferences.https(url)


@pytest.fixture
def workload_api():
    api = workloads.Workloads.__new__(workloads.Workloads)
    api.namespace = "fixture"
    api.definitions = [{"service": "ads", "kind": "Deployment", "name": "ads"}]
    api.api, api.apps, api.core, api.autoscaling = Mock(), Mock(), Mock(), Mock()
    api.api.sanitize_for_serialization.side_effect = lambda value: deepcopy(value)
    api.core.read_namespace.return_value = SimpleNamespace(
        metadata=SimpleNamespace(uid=str(uuid4()))
    )
    api.autoscaling.list_namespaced_horizontal_pod_autoscaler.return_value = {"items": []}
    original = {
        "metadata": {"uid": str(uuid4()), "resourceVersion": "5"},
        "spec": {"replicas": 2, "selector": {"matchLabels": {"app": "ads"}}},
        "status": {"replicas": 2},
    }
    api.apps.read_namespaced_deployment.side_effect = lambda *a, **kw: deepcopy(original)
    api.core.list_namespaced_pod.return_value = SimpleNamespace(items=[])
    return api, original


def test_fencing_requires_original_uid_zero_controller_and_zero_pods(workload_api):
    api, original = workload_api
    captured = api.snapshot()
    assert captured["items"][0]["replicas"] == 2
    assert not api.fenced(captured)
    api.set_replicas(captured, captured["items"][0], 0)
    body = api.apps.patch_namespaced_deployment.call_args.args[2]
    assert body[:2] == [
        {"op": "test", "path": "/metadata/uid", "value": original["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "5"},
    ]
    original["spec"]["replicas"] = original["status"]["replicas"] = 0
    assert api.fenced(captured)
    api.core.list_namespaced_pod.return_value.items = [{"metadata": {"deletionTimestamp": "now"}}]
    assert not api.fenced(captured)
    api.core.list_namespaced_pod.return_value.items = []
    original["metadata"]["uid"] = str(uuid4())
    assert not api.fenced(captured)
    with pytest.raises(protected.PreservationError):
        api.set_replicas(captured, captured["items"][0], 0)


@pytest.mark.parametrize("fault", ["operator", "hpa", "selector", "namespace"])
def test_unknown_controller_or_identity_cannot_be_treated_as_quiescent(workload_api, fault):
    api, original = workload_api
    captured = api.snapshot()
    if fault == "operator":
        original["metadata"]["ownerReferences"] = [{"uid": str(uuid4())}]
    elif fault == "hpa":
        api.autoscaling.list_namespaced_horizontal_pod_autoscaler.return_value = {
            "items": [{"spec": {"scaleTargetRef": {"name": "ads", "kind": "Deployment"}}}],
        }
    elif fault == "selector":
        original["spec"]["selector"]["matchLabels"] = {"app": "replacement"}
    else:
        api.core.read_namespace.return_value.metadata.uid = str(uuid4())
    if fault == "namespace":
        with pytest.raises(protected.PreservationError):
            api.fenced(captured)
    else:
        assert not api.fenced(captured)
