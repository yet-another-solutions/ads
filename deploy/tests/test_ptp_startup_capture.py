# ruff: noqa: F811
from __future__ import annotations

import contextlib
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from test_ptp_attachment import inputs, plugin  # noqa: F401
from test_ptp_release import Observer, operation, release, scope, snapshot  # noqa: F401


@pytest.fixture
def journaled(release, plugin, inputs, snapshot, monkeypatch):
    config, env, binding = inputs
    root = Path(config["stateDir"])
    records, namespaces, checks = [], {}, []
    for index, role in enumerate(("guest", "egress")):
        req = plugin.request(
            config,
            {
                **env,
                "CNI_CONTAINERID": snapshot["runtime_ids"][index * 2],
                "CNI_IFNAME": "eth0" if role == "guest" else "eth1",
                "CNI_NETNS": f"/vm/{index}",
                "CNI_ARGS": "K8S_POD_UID=" + snapshot["pod_uids"][index * 2],
            },
        )
        value = {
            **binding,
            "pod_uid": req["pod_uid"],
            "ifname": req["ifname"],
            "role": role,
            "generation": snapshot["generation"],
            "sandbox_id": snapshot["sandbox_id"],
            "relay_pod_uid": snapshot["pod_uids"][index * 2 + 1],
            "relay_runtime_id": snapshot["runtime_ids"][index * 2 + 1],
            "private": {
                "path": f"/private/{index}",
                "identity": snapshot["namespaces"][index * 3 + 1],
            },
            "transport": {
                "path": f"/transport/{index}",
                "identity": snapshot["namespaces"][index * 3 + 2],
            },
        }
        if role == "egress":
            value.update(address="10.10.30.1/24", gateway=None)
        record = {
            "request": req,
            "binding": value,
            "vm_identity": snapshot["namespaces"][index * 3],
            "result": {"incomplete": True},
            "indices": None,
        }
        plugin.save_record(root / (req["key"] + ".json"), record)
        records.append(record)
        for path, identity in (
            (req["netns"], record["vm_identity"]),
            (value["private"]["path"], value["private"]["identity"]),
            (value["transport"]["path"], value["transport"]["identity"]),
        ):
            namespaces[path] = identity

    @contextlib.contextmanager
    def namespace(path, expected):
        checks.append((path, expected))
        if path not in namespaces:
            raise FileNotFoundError
        release.require(namespaces[path] == expected, "namespace replaced")
        yield path

    monkeypatch.setattr(plugin, "namespace", namespace)
    monkeypatch.setattr(plugin, "ns_identity", lambda fd: namespaces[fd])
    monkeypatch.setattr(
        plugin, "links", lambda fd: {"eth0": {"link_index": 20 + int(fd.rsplit("/", 1)[1])}}
    )
    monkeypatch.setattr(plugin, "check", lambda *args: pytest.fail("not an operational CHECK"))
    observer = Observer()
    observer.links = deepcopy(snapshot["links"])
    observer.inspects = []

    def cri(command, option, fmt, runtime):
        assert (command, option, fmt) == ("inspectp", "-o", "json")
        observer.inspects.append(runtime)
        index = snapshot["runtime_ids"].index(runtime)
        return {
            "status": {
                "id": runtime,
                "state": "SANDBOX_NOTREADY",
                "metadata": {
                    "uid": snapshot["pod_uids"][index],
                    "namespace": snapshot["namespace"],
                },
            }
        }

    observer.cri = cri
    seen = []

    def observe(o, p, req):
        seen.append(req["pod_uid"])
        return deepcopy(next(r["binding"] for r in records if r["request"] == req))

    attestor = SimpleNamespace(observe_binding=observe)
    return SimpleNamespace(
        records=records,
        root=root,
        observer=observer,
        attestor=attestor,
        namespaces=namespaces,
        checks=checks,
        seen=seen,
    )


def capture(release, plugin, snapshot, f):
    return release.capture(plugin, f.attestor, f.observer, f.root, scope(snapshot), startup=True)


@pytest.mark.parametrize("progress", [None, {"vm": 11, "peer": 12}])
def test_interrupted_add_captures_same_complete_identity_inventory(
    release, plugin, snapshot, journaled, progress
):
    f = journaled
    for record in f.records:
        record["indices"] = progress
        plugin.save_record(f.root / (record["request"]["key"] + ".json"), record)
    value = capture(release, plugin, snapshot, f)
    assert value == snapshot
    assert len(f.seen) == len(f.observer.inspects) == 4
    assert len(f.checks) == 8  # Both VM and transport namespaces twice.
    assert not f.records[0]["result"].get("successful")
    assert all(plugin.read_record(f.root / (r["request"]["key"] + ".json")) == r for r in f.records)


def test_snapshot_order_is_role_canonical_when_journals_are_enumerated_in_reverse(
    release, plugin, snapshot, journaled, monkeypatch
):
    f = journaled
    original = release.journals
    monkeypatch.setattr(
        release, "journals", lambda loaded, root: iter(reversed(list(original(loaded, root))))
    )
    assert capture(release, plugin, snapshot, f) == snapshot


@pytest.mark.parametrize(
    "fault",
    [
        "missing-journal",
        "duplicate-role",
        "scope",
        "bad-progress",
        "bool-index",
        "request-command",
        "missing-vm-namespace",
        "replaced-vm-namespace",
        "host-peer",
        "cri-uid",
        "cri-id",
        "cri-namespace",
        "cri-unknown-state",
        "binding",
    ],
)
def test_incomplete_or_foreign_runtime_evidence_is_not_capture(
    release, plugin, snapshot, journaled, fault
):
    f = journaled
    record = f.records[0]
    path = f.root / (record["request"]["key"] + ".json")
    if fault == "missing-journal":
        path.unlink()
    elif fault in ("duplicate-role", "scope", "bad-progress", "bool-index", "request-command"):
        if fault == "duplicate-role":
            record["binding"].update(role="egress", address="10.10.30.1/24", gateway=None)
        elif fault == "scope":
            record["binding"]["sandbox_id"] = str(uuid4())
        elif fault == "bad-progress":
            record["indices"] = {}
        elif fault == "bool-index":
            record["indices"] = {"vm": True, "peer": 2}
        else:
            record["request"]["command"] = "DEL"
        plugin.save_record(path, record)
    elif fault == "missing-vm-namespace":
        del f.namespaces[record["request"]["netns"]]
    elif fault == "replaced-vm-namespace":
        f.namespaces[record["request"]["netns"]] = [7, 9]
    elif fault == "host-peer":
        f.observer.links = []
    elif fault == "binding":
        f.attestor.observe_binding = lambda *args: {}
    else:
        original = f.observer.cri

        def cri(*args):
            value = original(*args)
            status = value["status"]
            if fault == "cri-id":
                status["id"] = "f" * 64
            elif fault == "cri-unknown-state":
                status["state"] = "UNKNOWN"
            else:
                status["metadata"]["uid" if fault == "cri-uid" else "namespace"] = "changed"
            return value

        f.observer.cri = cri
    with pytest.raises((ValueError, FileNotFoundError)):
        capture(release, plugin, snapshot, f)
    assert not list(f.root.glob("release-*.json"))


@pytest.mark.parametrize(
    "fault", ["journal", "binding", "cri", "namespace", "boot", "host-peer", "transport-peer"]
)
def test_changed_evidence_at_final_recheck_is_not_captured(
    release, plugin, snapshot, journaled, monkeypatch, fault
):
    f = journaled
    original = f.observer.cri
    count = 0

    def cri(*args):
        nonlocal count
        count += 1
        value = original(*args)
        if count == 2:
            record = f.records[0]
            if fault == "journal":
                path = f.root / (record["request"]["key"] + ".json")
                changed = plugin.read_record(path)
                changed["indices"] = {"vm": 11, "peer": 12}
                plugin.save_record(path, changed)
            elif fault == "binding":
                f.attestor.observe_binding = lambda *args: {}
            elif fault == "namespace":
                f.namespaces[record["request"]["netns"]] = [9, 10]
            elif fault == "boot":
                monkeypatch.setattr(release, "boot_id", lambda: str(uuid4()))
            elif fault == "host-peer":
                f.observer.links[0]["ifname"] = "replaced"
            elif fault == "transport-peer":
                original_links = plugin.links
                monkeypatch.setattr(
                    plugin,
                    "links",
                    lambda fd: {
                        "eth0": {
                            "link_index": 999
                            if fd.endswith("/0")
                            else original_links(fd)["eth0"]["link_index"]
                        }
                    },
                )
        if fault == "cri" and count == 3:
            value["status"]["metadata"]["uid"] = str(uuid4())
        return value

    f.observer.cri = cri
    with pytest.raises(ValueError):
        capture(release, plugin, snapshot, f)
    assert not list(f.root.glob("release-*.json"))


def test_startup_action_requires_fence_and_never_overwrites_capture(
    release, plugin, snapshot, operation, monkeypatch
):
    request, observer = operation
    request["action"] = "capture-startup"
    seen = []

    def captured(*args, **kwargs):
        seen.append(kwargs)
        return deepcopy(snapshot)

    monkeypatch.setattr(release, "capture", captured)
    result = release.perform(request)
    assert seen == [{"startup": True}]
    assert result["release_inventory_captured"] and not result["observed_runtime_released"]
    assert release.perform({**request, "action": "capture"}) == result
    assert release.perform(request) == result
    assert seen == [{"startup": True}]
    fence = Path(request["stateDir"]) / ("retired-" + request["generation"] + ".json")
    fence.unlink()
    with pytest.raises(FileNotFoundError):
        release.perform(request)
    assert observer.reads == 0


def test_retained_partial_journal_blocks_runtime_release(
    release, plugin, snapshot, journaled, tmp_path, monkeypatch
):
    f = journaled
    value = capture(release, plugin, snapshot, f)
    observer = Observer()
    monkeypatch.setattr(release, "process_references", lambda *args: 0)
    result = release.observe(plugin, observer, f.root, value)
    assert result["leftovers"]["journals"] == 2
    assert not result["observed_runtime_released"] and not result["generation_retired"]
