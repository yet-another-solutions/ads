"""Exercise the operational reconciler without secrets or live realm mutation."""

import importlib.util
import io
from pathlib import Path
from unittest.mock import Mock, call

import pytest


@pytest.fixture
def identity(monkeypatch):
    monkeypatch.setenv("ADS_SLICE6_KEYCLOAK_URL", "https://identity.example")
    monkeypatch.setattr("sys.stdin", io.StringIO("{}"))
    path = Path(__file__).parents[1] / "lab/sandbox-identity/keycloak.py"
    spec = importlib.util.spec_from_file_location("lifecycle_identity", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reconciler_removes_only_legacy_subject_mapping_and_attribute(identity):
    user = {
        "id": "service-user",
        "attributes": {
            "ads_service_client_uuid": ["client"],
            "unrelated": ["preserve"],
        },
    }
    identity.api = Mock(
        side_effect=[
            [
                {"id": "legacy", "name": "ads-service-subject"},
                {"id": "audience", "name": "audience-manager", "config": {}},
            ],
            None,
            user,
            None,
        ]
    )
    identity.native_service_subject({"id": "client"})
    root = "/admin/realms/ads/clients/client"
    assert identity.api.call_args_list == [
        call("GET", root + "/protocol-mappers/models"),
        call("DELETE", root + "/protocol-mappers/models/legacy"),
        call("GET", root + "/service-account-user"),
        call("PUT", "/admin/realms/ads/users/service-user", user),
    ]
    assert user["attributes"] == {"unrelated": ["preserve"]}


def test_native_subject_reconciliation_is_idempotent(identity):
    identity.api = Mock(side_effect=[[], {"id": "service-user"}])
    identity.native_service_subject({"id": "client"})
    assert all(c.args[0] == "GET" for c in identity.api.call_args_list)


def test_unexpected_subject_override_requires_review(identity):
    identity.api = Mock(
        return_value=[
            {"id": "legacy", "name": "ads-service-subject"},
            {"id": "custom", "name": "custom", "config": {"claim.name": "sub"}},
        ]
    )
    with pytest.raises(RuntimeError, match="Unexpected subject"):
        identity.native_service_subject({"id": "client"})
    identity.api.assert_called_once()


def test_lifecycle_proof_exchanges_both_hops_with_original_service_subject(identity):
    identity.exchange = Mock(side_effect=["ipc-token", "manager-token"])
    identity.verify = Mock()
    identity.prove_lifecycle_round_trip("initial-service-token", "service-user")
    assert identity.exchange.call_args_list == [
        call("ads-sandbox-manager", "ads-sandbox-ipc", "initial-service-token"),
        call("ads-sandbox-ipc", "ads-sandbox-manager", "ipc-token"),
    ]
    assert identity.verify.call_args_list == [
        call("ipc-token", "ads-sandbox-ipc", "ads-sandbox-manager", "service-user", user=False),
        call("manager-token", "ads-sandbox-manager", "ads-sandbox-ipc", "service-user", user=False),
    ]
