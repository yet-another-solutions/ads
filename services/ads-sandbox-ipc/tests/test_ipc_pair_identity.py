# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from ads_sandbox_ipc.config import EgressPair, PairedGuest, load_settings
from ads_sandbox_ipc.guest import Pod
from ads_sandbox_ipc.kube import KubeClient
from test_ipc_app import configure, tls_settings  # noqa: F401
from test_ipc_kube import kube  # noqa: F401


def association():
    return EgressPair(
        uuid4(),
        "https://egress.test",
        ("https://local.test/health", "https://peer.test/health"),
        uuid4(),
    )


@pytest.fixture
def paired(kube):
    guest = PairedGuest("ads-guest-" + str(uuid4()), str(uuid4()), uuid4())
    kube.settings = replace(kube.settings, egress=association(), paired_guest=guest)
    item = deepcopy(kube.api.read_namespaced_pod.return_value)
    item.metadata.name = guest.name
    item.metadata.uid = guest.uid
    item.metadata.namespace = kube.settings.namespace
    item.metadata.labels.update(
        {
            "ads.io/attachment-generation": str(guest.generation),
            "ads.io/project-id": str(kube.settings.egress.project_id),
            "app.kubernetes.io/component": "ads-sandbox",
        }
    )
    kube.api.list_namespaced_pod.return_value.items = [item]
    kube.api.read_namespaced_pod.return_value = item
    return kube


@pytest.mark.anyio
async def test_discovery_and_every_exec_bind_exact_pod_and_generation(paired, monkeypatch):
    guest = paired.settings.paired_guest
    expected = Pod(guest.name, guest.uid)
    assert await paired.ready_pod() == expected
    selector = paired.api.list_namespaced_pod.call_args.kwargs["label_selector"]
    assert set(selector.split(",")) == {
        f"ads.io/sandbox-id={paired.settings.sandbox_id}",
        f"ads.io/attachment-generation={guest.generation}",
        f"ads.io/project-id={paired.settings.egress.project_id}",
        "app.kubernetes.io/component=ads-sandbox",
    }
    socket = SimpleNamespace(subprotocol="v5.channel.k8s.io", send=AsyncMock(), close=AsyncMock())
    connect = AsyncMock(return_value=socket)
    monkeypatch.setattr("ads_sandbox_ipc.kube.connect", connect)
    await paired.start(expected, ["true"], b"")
    assert f"/pods/{guest.name}/exec?" in connect.call_args.args[0]
    assert connect.call_args.kwargs["additional_headers"] == {
        "Authorization": "Bearer projected-sa-token"
    }
    await socket.close()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "fault",
    [
        "name",
        "uid",
        "namespace",
        "generation",
        "project",
        "component",
        "sandbox",
        "deleting",
    ],
)
async def test_foreign_or_stale_labeled_guest_is_never_a_fallback(paired, monkeypatch, fault):
    guest = paired.settings.paired_guest
    item = paired.api.read_namespaced_pod.return_value
    if fault in ("name", "uid", "namespace"):
        setattr(item.metadata, fault, "foreign")
    elif fault == "deleting":
        item.metadata.deletion_timestamp = "now"
    else:
        key = {
            "generation": "ads.io/attachment-generation",
            "project": "ads.io/project-id",
            "component": "app.kubernetes.io/component",
            "sandbox": "ads.io/sandbox-id",
        }[fault]
        item.metadata.labels[key] = "foreign"
    connect = AsyncMock()
    monkeypatch.setattr("ads_sandbox_ipc.kube.connect", connect)
    assert await paired.ready_pod() is None
    with pytest.raises(RuntimeError, match="identity changed"):
        await paired.start(Pod(guest.name, guest.uid), ["true"], b"")
    connect.assert_not_awaited()
    paired.configuration.get_api_key_with_prefix.assert_not_called()


@pytest.mark.anyio
@pytest.mark.parametrize("fault", ["name", "uid"])
async def test_requested_exec_identity_cannot_redirect_even_with_correct_api_reply(
    paired, monkeypatch, fault
):
    guest = paired.settings.paired_guest
    pod = Pod(
        "foreign" if fault == "name" else guest.name, "foreign" if fault == "uid" else guest.uid
    )
    connect = AsyncMock()
    monkeypatch.setattr("ads_sandbox_ipc.kube.connect", connect)
    with pytest.raises(RuntimeError, match="identity changed"):
        await paired.start(pod, ["true"], b"")
    paired.api.read_namespaced_pod.assert_not_called()
    connect.assert_not_awaited()


@pytest.mark.anyio
async def test_nonmatching_extra_pods_cannot_replace_exact_guest(paired):
    correct = paired.api.read_namespaced_pod.return_value
    old = deepcopy(correct)
    old.metadata.uid = str(uuid4())
    old.metadata.labels["ads.io/attachment-generation"] = str(uuid4())
    paired.api.list_namespaced_pod.return_value.items = [old, correct]
    assert await paired.ready_pod() == Pod(correct.metadata.name, correct.metadata.uid)
    paired.api.list_namespaced_pod.return_value.items = [old]
    assert await paired.ready_pod() is None


def pair_environment():
    return {
        "PROJECT_ID": str(uuid4()),
        "EGRESS_URL": "https://egress.test",
        "LOCAL_RELAY_HEALTH_URL": "https://local.test/health",
        "PEER_RELAY_HEALTH_URL": "https://peer.test/health",
        "ADS_SERVICE_SUBJECT": str(uuid4()),
        "GUEST_POD_NAME": "ads-guest-" + str(uuid4()),
        "GUEST_POD_UID": str(uuid4()),
        "ATTACHMENT_GENERATION": str(uuid4()),
    }


def test_production_loader_receives_complete_immutable_pair(monkeypatch, tls_settings):
    configure(monkeypatch, tls_settings)
    env = pair_environment()
    for name, value in env.items():
        monkeypatch.setenv("ADS_SANDBOX_IPC_" + name, value)
    settings = load_settings()
    assert settings.paired_guest.name == env["GUEST_POD_NAME"]
    assert settings.paired_guest.uid == env["GUEST_POD_UID"]
    assert str(settings.paired_guest.generation) == env["ATTACHMENT_GENERATION"]
    assert str(settings.egress.project_id) == env["PROJECT_ID"]
    assert settings.egress.base_url == env["EGRESS_URL"]
    assert settings.egress.relay_urls == (
        env["LOCAL_RELAY_HEALTH_URL"],
        env["PEER_RELAY_HEALTH_URL"],
    )
    assert str(settings.egress.ads_service_subject) == env["ADS_SERVICE_SUBJECT"]


@pytest.mark.parametrize("missing", list(pair_environment()))
def test_partial_manager_handoff_fails_before_network(monkeypatch, tls_settings, missing):
    configure(monkeypatch, tls_settings)
    for name, value in pair_environment().items():
        monkeypatch.setenv("ADS_SANDBOX_IPC_" + name, "" if name == missing else value)
    with pytest.raises((ValueError, RuntimeError)):
        load_settings()


def test_paired_runtime_never_silently_falls_back_to_legacy_guest_selection(ipc, monkeypatch):
    load = Mock()
    monkeypatch.setattr("ads_sandbox_ipc.kube.config.load_incluster_config", load)
    with pytest.raises(ValueError, match="exact manager-provided guest"):
        KubeClient(replace(ipc.settings, egress=association()))
    load.assert_not_called()
    with pytest.raises(ValueError, match="egress association"):
        replace(ipc.settings, paired_guest=PairedGuest("guest", "uid", uuid4()))


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", ""),
        ("name", "a" * 64),
        ("name", "a/b"),
        ("name", None),
        ("uid", ""),
        ("uid", " uid "),
        ("uid", None),
        ("generation", "not-uuid"),
    ],
)
def test_paired_guest_requires_valid_immutable_inputs(field, value):
    values = {"name": "guest", "uid": "uid", "generation": uuid4(), field: value}
    with pytest.raises(ValueError):
        PairedGuest(**values)
