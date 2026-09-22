from __future__ import annotations

import contextlib
import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

SCRIPT = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-ptp-attest"


@pytest.fixture
def attest():
    loader = importlib.machinery.SourceFileLoader("node_attestor", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def fixture(attest):
    config = {
        "node": "worker",
        "namespace": "sandboxes",
        "network": "ads-private",
        "kubeconfig": "/protected/config",
        "kubectl": "/usr/bin/kubectl",
        "crictl": "/usr/bin/crictl",
        "cri_endpoint": "unix:///run/runtime.sock",
        "relay_image": "registry.example/relay:version",
        "relay_image_id": "sha256:" + "a" * 64,
        "relay_container": "relay",
        "guest_runtime": "kata-private",
        "egress_runtime": "kata-egress",
        "transport_mtu": 1450,
    }
    labels = {name: str(uuid4()) for name in attest.LABELS}
    vm = {
        "metadata": {
            "uid": str(uuid4()),
            "name": "guest",
            "namespace": config["namespace"],
            "labels": {**labels, attest.COMPONENT: "ads-sandbox"},
        },
        "spec": {"nodeName": config["node"], "runtimeClassName": config["guest_runtime"]},
        "status": {"phase": "Pending"},
    }
    relay = {
        "metadata": {
            "uid": str(uuid4()),
            "name": "relay",
            "namespace": config["namespace"],
            "labels": {**labels, attest.COMPONENT: "ads-sandbox-relay"},
        },
        "spec": {
            "nodeName": config["node"],
            "containers": [{"name": "relay", "image": config["relay_image"]}],
        },
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "relay",
                    "containerID": "containerd://" + "b" * 64,
                    "state": {"running": {}},
                }
            ],
        },
    }
    sandbox = {
        "id": "c" * 64,
        "metadata": {k: relay["metadata"][k] for k in ("uid", "namespace", "name")},
        "state": "SANDBOX_READY",
    }
    container = {
        "status": {
            "id": "b" * 64,
            "state": "CONTAINER_RUNNING",
            "metadata": {"name": "relay"},
            "labels": {
                "io.kubernetes.pod.uid": relay["metadata"]["uid"],
                "io.kubernetes.pod.namespace": config["namespace"],
            },
            "imageRef": config["relay_image_id"],
        },
        "info": {"pid": 202, "sandboxID": sandbox["id"]},
    }
    return SimpleNamespace(config=config, vm=vm, relay=relay, sandbox=sandbox, container=container)


def test_pair_selection_binds_full_identity_and_both_runtime_roles(attest, fixture):
    f = fixture
    result = attest.select_pair([f.vm, f.relay], f.vm["metadata"]["uid"], f.config)
    assert result == (f.vm, f.relay, "guest", "b" * 64)
    f.vm["metadata"]["labels"][attest.COMPONENT] = "ads-sandbox-egress"
    f.vm["spec"]["runtimeClassName"] = f.config["egress_runtime"]
    f.relay["metadata"]["labels"][attest.COMPONENT] = "ads-sandbox-egress-relay"
    assert attest.select_pair([f.vm, f.relay], f.vm["metadata"]["uid"], f.config)[2] == "egress"


@pytest.mark.parametrize(
    "fault",
    [
        "vm-uid",
        "vm-node",
        "vm-terminating",
        "vm-host",
        "vm-runtime",
        "vm-phase",
        "relay-node",
        "relay-namespace",
        "relay-terminating",
        "relay-host",
        "relay-runtime",
        "relay-image",
        "relay-container",
        "relay-phase",
        "relay-stopped",
        "relay-id",
        "generation",
        "sandbox",
        "session",
        "project",
        "ambiguous",
        "missing",
    ],
)
def test_pair_selection_denies_wrong_replaced_or_ambiguous_identity(attest, fixture, fault):
    f = fixture
    pods = [f.vm, f.relay]
    uid = f.vm["metadata"]["uid"]
    if fault == "vm-uid":
        uid = str(uuid4())
    elif fault.endswith("-node"):
        getattr(f, fault.split("-")[0])["spec"]["nodeName"] = "foreign"
    elif fault.endswith("-terminating"):
        getattr(f, fault.split("-")[0])["metadata"]["deletionTimestamp"] = "now"
    elif fault.endswith("-host"):
        getattr(f, fault.split("-")[0])["spec"]["hostNetwork"] = True
    elif fault.endswith("-runtime"):
        getattr(f, fault.split("-")[0])["spec"]["runtimeClassName"] = "wrong"
    elif fault.endswith("-phase"):
        getattr(f, fault.split("-")[0])["status"]["phase"] = "Succeeded"
    elif fault == "relay-namespace":
        f.relay["metadata"]["namespace"] = "other"
    elif fault == "relay-image":
        f.relay["spec"]["containers"][0]["image"] = "other"
    elif fault == "relay-container":
        f.relay["spec"]["containers"].append({"name": "unexpected"})
    elif fault == "relay-stopped":
        f.relay["status"]["containerStatuses"][0]["state"] = {"terminated": {}}
    elif fault == "relay-id":
        f.relay["status"]["containerStatuses"][0]["containerID"] = "containerd://short"
    elif fault in ("generation", "sandbox", "session", "project"):
        name = "ads.io/" + ("attachment-generation" if fault == "generation" else fault + "-id")
        f.relay["metadata"]["labels"][name] = str(uuid4())
    elif fault == "ambiguous":
        pods.append(copy.deepcopy(f.relay))
    elif fault == "missing":
        pods.pop()
    with pytest.raises(ValueError):
        attest.select_pair(pods, uid, f.config)


class RuntimeObserver:
    def __init__(self, f):
        self.config, self.f = f.config, f

    def pods(self):
        return [self.f.vm, self.f.relay]

    def cri(self, *args):
        if args[0] == "pods":
            return {"items": [self.f.sandbox]}
        if args[0] == "inspectp":
            return {"status": self.f.sandbox, "info": {"pid": 101}}
        assert args[0] == "inspect"
        return self.f.container


@pytest.mark.parametrize("fault", [None, "uid", "namespace", "image", "sandbox", "state", "pid"])
def test_cri_requires_exact_pod_container_image_and_process(attest, fixture, fault):
    f = fixture
    if fault in ("uid", "namespace"):
        f.container["status"]["labels"]["io.kubernetes.pod." + fault] = "foreign"
    elif fault == "image":
        f.container["status"]["imageRef"] = "sha256:" + "d" * 64
    elif fault == "sandbox":
        f.container["info"]["sandboxID"] = "e" * 64
    elif fault == "state":
        f.container["status"]["state"] = "CONTAINER_EXITED"
    elif fault == "pid":
        f.container["info"]["pid"] = True
    if fault is None:
        assert attest.runtime_identity(RuntimeObserver(f), f.relay, "b" * 64) == (
            "c" * 64,
            (101, 202),
        )
    else:
        with pytest.raises(ValueError):
            attest.runtime_identity(RuntimeObserver(f), f.relay, "b" * 64)


@pytest.mark.parametrize("fault", ["ticks", "exited"])
def test_process_pin_and_replacement_detection(attest, monkeypatch, fault):
    # The sandbox Python lacks pidfd_open. Model its pollable descriptor here;
    # the real image/kernel gate invokes the actual syscall, without a fallback.
    reader, writer = os.pipe()
    monkeypatch.setattr(attest.os, "pidfd_open", lambda pid: os.dup(reader), raising=False)
    original = attest.ticks
    try:
        with pytest.raises(ValueError, match="process replaced"):
            with attest.processes((os.getpid(),)) as check:
                check()
                if fault == "ticks":
                    monkeypatch.setattr(attest, "ticks", lambda pid: "replaced")
                else:
                    os.write(writer, b"exited")
                check()
    finally:
        monkeypatch.setattr(attest, "ticks", original)
        os.close(reader)
        os.close(writer)


def test_api_observer_forces_tls_node_namespace_and_bounded_requests(attest, fixture, monkeypatch):
    calls = []
    observer = attest.Observer(fixture.config)
    monkeypatch.setattr(observer, "command", lambda *args: calls.append(args) or {"items": []})
    assert observer.pods() == []
    args = calls[0]
    assert "--insecure-skip-tls-verify=false" in args
    assert "--request-timeout=3s" in args
    assert "--field-selector=spec.nodeName=worker" in args
    assert args[args.index("-n") + 1] == "sandboxes"
    assert not any(word in args for word in ("secrets", "exec", "delete", "patch", "apply"))
    observer.cri("pods", "-o", "json")
    assert "--timeout=3s" in calls[-1]
    assert "--runtime-endpoint=unix:///run/runtime.sock" in calls[-1]


@pytest.mark.parametrize("fault", [None, "journal", "namespace", "replaced"])
def test_full_observation_rechecks_live_pair_and_matches_namespace_journal(
    attest, fixture, monkeypatch, fault
):
    f = fixture
    observer = RuntimeObserver(f)
    plugin = attest.cni_module()
    req = {"pod_uid": f.vm["metadata"]["uid"], "network": "ads-private", "ifname": "eth0"}
    generation = f.vm["metadata"]["labels"]["ads.io/attachment-generation"]
    calls = []

    @contextlib.contextmanager
    def namespace(path):
        calls.append(path)
        yield 10 if "/root/run/netns/" in path else 20

    journal = {
        "complete": True,
        "pod_uid": f.relay["metadata"]["uid"],
        "generation": generation,
        "sandbox_id": f.vm["metadata"]["labels"]["ads.io/sandbox-id"],
        "private": [1, 10],
        "transport": [1, 20],
    }
    if fault == "journal":
        journal["generation"] = str(uuid4())
    if fault == "namespace":
        journal["private"] = [1, 99]
    monkeypatch.setattr(plugin, "namespace", namespace)
    monkeypatch.setattr(plugin, "read_record", lambda path: journal)
    monkeypatch.setattr(attest.os, "fstat", lambda fd: SimpleNamespace(st_dev=1, st_ino=fd))
    monkeypatch.setattr(attest.fcntl, "ioctl", lambda *args: 0x40000000)
    monkeypatch.setattr(attest, "processes", lambda pids: contextlib.nullcontext(lambda: None))
    observations = []

    def pods():
        observations.append(True)
        if fault == "replaced" and len(observations) == 2:
            replacement = copy.deepcopy(f.relay)
            replacement["metadata"]["uid"] = str(uuid4())
            return [f.vm, replacement]
        return [f.vm, f.relay]

    monkeypatch.setattr(observer, "pods", pods)
    if fault:
        with pytest.raises(ValueError):
            attest.observe_binding(observer, plugin, req)
    else:
        result = attest.observe_binding(observer, plugin, req)
        assert result["private"]["identity"] == [1, 10]
        assert result["transport"]["identity"] == [1, 20]
        assert result["relay_runtime_id"] == f.sandbox["id"]
        assert result["mtu"] == 1340
        assert result["address"] == "10.10.30.2/24" and result["gateway"] == "10.10.30.1"
        assert len(observations) == 2 and len(calls) == 3


def test_cli_cannot_adopt_a_stale_static_record_without_live_attestation(
    attest, monkeypatch, capsys
):
    plugin = attest.cni_module()
    import io
    import sys

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b'{"cniVersion":"1.0.0"}')))
    monkeypatch.setenv("CNI_COMMAND", "ADD")
    monkeypatch.setattr(plugin.os, "geteuid", lambda: 0)
    monkeypatch.setattr(plugin, "perform", lambda *args: pytest.fail("stale record used"))
    with pytest.raises(SystemExit):
        plugin.main()
    assert json.loads(capsys.readouterr().out)["details"] == "ValueError"


@pytest.mark.parametrize(
    "fault", [None, "extra", "mtu", "remote-cri", "image-id", "name", "credentials", "executable"]
)
def test_platform_configuration_is_exact_local_and_protected(
    attest, fixture, tmp_path, monkeypatch, fault
):
    config = fixture.config
    for name in ("kubeconfig", "kubectl", "crictl"):
        path = tmp_path / name
        path.write_text("fixture")
        path.chmod(0o600 if name == "kubeconfig" else 0o700)
        config[name] = str(path)
    original = Path.lstat

    def info(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        return SimpleNamespace(st_mode=value.st_mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", info)
    if fault == "extra":
        config["unknown"] = True
    elif fault == "mtu":
        config["transport_mtu"] = True
    elif fault == "remote-cri":
        config["cri_endpoint"] = "https://runtime.invalid"
    elif fault == "image-id":
        config["relay_image_id"] = "latest"
    elif fault == "name":
        config["namespace"] = "../foreign"
    elif fault == "credentials":
        Path(config["kubeconfig"]).chmod(0o644)
    elif fault == "executable":
        Path(config["crictl"]).chmod(0o777)
    if fault is None:
        assert attest.validate(config) == config
    else:
        with pytest.raises(ValueError):
            attest.validate(config)


def test_failed_refresh_never_publishes_or_reuses_an_old_binding(
    attest, fixture, tmp_path, monkeypatch
):
    plugin = attest.cni_module()
    req = {"pod_uid": fixture.vm["metadata"]["uid"]}
    monkeypatch.setattr(attest.os, "geteuid", lambda: 0)
    monkeypatch.setattr(plugin, "read_record", lambda path: fixture.config)
    monkeypatch.setattr(attest, "validate", lambda value: value)
    monkeypatch.setattr(
        plugin, "save_record", lambda *args: pytest.fail("failure published a binding")
    )

    def failed(*args):
        raise RuntimeError("API unavailable")

    monkeypatch.setattr(attest, "observe_binding", failed)
    with pytest.raises(RuntimeError, match="API unavailable"):
        attest.refresh(tmp_path / "config", req, tmp_path, plugin)
