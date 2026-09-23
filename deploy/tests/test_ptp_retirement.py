# ruff: noqa: F811
from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
from test_ptp_attachment import inputs, kernel, plugin  # noqa: F401


def retirement(config, record):
    return {
        "stateDir": config["stateDir"],
        **{key: record[key] for key in ("network", "sandbox_id", "generation")},
    }


def fence_path(config, record):
    return Path(config["stateDir"]) / ("retired-" + record["generation"] + ".json")


def test_fence_keeps_existing_attachment_and_del_available(plugin, inputs, kernel):
    config, env, record = inputs
    output = plugin.perform(config, env)
    request = retirement(config, record)
    reply = plugin.retire(request)
    assert reply == {
        **{key: record[key] for key in ("network", "sandbox_id", "generation")},
        "attachment_admission_fenced": True,
        "runtime_release_proven": False,
    }
    assert plugin.retire(request) == reply
    assert "eth0" in kernel[3][10]  # Fencing does not claim existing traffic stopped.
    config["prevResult"] = output
    env["CNI_COMMAND"] = "CHECK"
    with pytest.raises(ValueError, match="generation retired"):
        plugin.perform(config, env)
    env["CNI_COMMAND"] = "DEL"
    assert plugin.perform(config, env) is None
    assert plugin.perform(config, env) is None
    assert not kernel[2].exists() and set(kernel[3][10]) == {"lo"}
    assert fence_path(config, record).exists()
    env["CNI_COMMAND"] = "ADD"
    with pytest.raises(ValueError, match="generation retired"):
        plugin.perform(config, env)
    assert not kernel[2].exists() and set(kernel[3][10]) == {"lo"}


@pytest.mark.parametrize("role", ["guest", "egress"])
def test_fence_covers_late_runtime_and_pod_ids_on_both_sides(plugin, inputs, monkeypatch, role):
    config, env, record = inputs
    plugin.retire(retirement(config, record))
    monkeypatch.setattr(plugin, "add", lambda *args: pytest.fail("retired ADD reached kernel"))
    record.update(pod_uid=str(uuid4()), relay_pod_uid=str(uuid4()), role=role)
    if role == "egress":
        record.update(address="10.10.30.1/24", gateway=None)
    env.update(CNI_CONTAINERID="e" * 64, CNI_ARGS="K8S_POD_UID=" + record["pod_uid"])
    plugin.save_record(Path(config["bindingDir"]) / (record["pod_uid"] + ".json"), record)
    with pytest.raises(ValueError, match="generation retired"):
        plugin.perform(config, env)


def test_another_generation_is_not_fenced(plugin, inputs, monkeypatch):
    config, env, record = inputs
    other = {**record, "generation": str(uuid4())}
    plugin.retire(retirement(config, other))
    monkeypatch.setattr(plugin, "add", lambda *args: {"test_kernel_called": True})
    assert plugin.perform(config, env) == {"test_kernel_called": True}
    assert not fence_path(config, record).exists()


def test_fence_cannot_report_success_during_actual_inflight_add(plugin, inputs, monkeypatch):
    config, env, record = inputs
    entered, finish = Event(), Event()

    def delayed_add(*args):
        entered.set()
        assert finish.wait(5)
        return {"test_kernel_finished": True}

    monkeypatch.setattr(plugin, "add", delayed_add)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(plugin.perform, config, env)
        try:
            assert entered.wait(5)
            with pytest.raises(BlockingIOError):
                plugin.retire(retirement(config, record))
            assert not fence_path(config, record).exists()
        finally:
            finish.set()
        assert future.result(5) == {"test_kernel_finished": True}
    assert plugin.retire(retirement(config, record))["attachment_admission_fenced"]
    with pytest.raises(ValueError, match="generation retired"):
        plugin.perform(config, env)


def test_delayed_attestation_cannot_cross_completed_fence(plugin, inputs, monkeypatch):
    config, env, record = inputs
    entered, finish = Event(), Event()
    read = plugin.read_record

    def delayed_read(path):
        value = read(path)
        if path.parent == Path(config["bindingDir"]):
            entered.set()
            assert finish.wait(5)
        return value

    monkeypatch.setattr(plugin, "read_record", delayed_read)
    monkeypatch.setattr(plugin, "add", lambda *args: pytest.fail("late ADD reached kernel"))
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(plugin.perform, config, env)
        try:
            assert entered.wait(5)
            assert plugin.retire(retirement(config, record))["attachment_admission_fenced"]
        finally:
            finish.set()
        with pytest.raises(ValueError, match="generation retired"):
            future.result(5)


def test_busy_retirement_lock_blocks_add_and_releases_on_exception(plugin, inputs, monkeypatch):
    config, env, record = inputs
    monkeypatch.setattr(plugin, "add", lambda *args: {"test_kernel_called": True})
    with plugin.generation_lock(config["stateDir"], record["generation"]):
        with pytest.raises(BlockingIOError):
            plugin.perform(config, env)
        with pytest.raises(BlockingIOError):
            plugin.retire(retirement(config, record))
    assert plugin.perform(config, env) == {"test_kernel_called": True}


@pytest.mark.parametrize(
    "change",
    [
        {"generation": "../escape"},
        {"generation": None},
        {"sandbox_id": "bad"},
        {"sandbox_id": 1},
        {"network": "../foreign"},
        {"network": None},
        {"extra": True},
    ],
)
def test_invalid_retirement_never_writes_fence(plugin, inputs, change):
    config, _, record = inputs
    with pytest.raises((ValueError, TypeError)):
        plugin.retire({**retirement(config, record), **change})
    assert not list(Path(config["stateDir"]).glob("retired-*.json"))


@pytest.mark.parametrize("field", ["network", "sandbox_id"])
def test_fence_identity_cannot_be_reassigned(plugin, inputs, field):
    config, _, record = inputs
    request = retirement(config, record)
    plugin.retire(request)
    before = fence_path(config, record).read_bytes()
    with pytest.raises(ValueError, match="identity changed"):
        plugin.retire({**request, field: "other" if field == "network" else str(uuid4())})
    assert fence_path(config, record).read_bytes() == before


@pytest.mark.parametrize("fault", ["symlink", "dangling", "permissions", "corrupt", "empty"])
def test_invalid_fence_never_allows_admission_or_overwrite(plugin, inputs, monkeypatch, fault):
    config, env, record = inputs
    request = retirement(config, record)
    plugin.retire(request)
    path = fence_path(config, record)
    if fault in ("symlink", "dangling"):
        target = path.with_suffix(".target")
        path.rename(target)
        path.symlink_to(target)
        if fault == "dangling":
            target.unlink()
    elif fault == "permissions":
        path.chmod(0o644)
    elif fault == "corrupt":
        path.write_text("not JSON")
    else:
        plugin.save_record(path, {})
    monkeypatch.setattr(plugin, "add", lambda *args: pytest.fail("bad fence reached kernel"))
    for operation in (
        lambda: plugin.perform(config, env),
        lambda: plugin.retire(request),
    ):
        with pytest.raises((ValueError, OSError)):
            operation()
    assert path.exists() or path.is_symlink()


@pytest.mark.parametrize("fault", ["lock-symlink", "lock-permissions", "lock-fifo", "directory"])
def test_generation_lock_and_directory_protections(plugin, inputs, fault):
    config, env, record = inputs
    root = Path(config["stateDir"])
    path = root / ("generation-" + record["generation"] + ".lock")
    if fault == "directory":
        root.chmod(0o755)
    elif fault == "lock-symlink":
        path.symlink_to(root / "absent")
    elif fault == "lock-fifo":
        os.mkfifo(path, 0o600)
    else:
        path.touch(mode=0o644)
    for operation in (
        lambda: plugin.perform(config, env),
        lambda: plugin.retire(retirement(config, record)),
    ):
        with pytest.raises((ValueError, OSError)):
            operation()
    assert not fence_path(config, record).exists()


def test_failed_directory_sync_is_not_success_and_retry_reasserts_durability(
    plugin, inputs, monkeypatch
):
    config, env, record = inputs
    original = plugin.sync_directory

    def failed(path):
        raise OSError("injected directory fsync failure")

    monkeypatch.setattr(plugin, "sync_directory", failed)
    with pytest.raises(OSError, match="fsync"):
        plugin.retire(retirement(config, record))
    assert fence_path(config, record).exists()
    with pytest.raises(ValueError, match="generation retired"):
        plugin.perform(config, env)
    synced = []

    def observed(path):
        synced.append(path)
        original(path)

    monkeypatch.setattr(plugin, "sync_directory", observed)
    assert plugin.retire(retirement(config, record))["attachment_admission_fenced"]
    assert synced == [Path(config["stateDir"])]
    assert not list(Path(config["stateDir"]).glob(".pending-*"))


def test_cli_rejects_unprivileged_caller_without_echoing_input():
    if os.geteuid() == 0:
        pytest.skip("root success is covered by the tooling image kernel smoke")
    script = Path(__file__).parents[2] / "services/ads-ptp-tools/ads-ptp-retire"
    reply = subprocess.run(
        [sys.executable, str(script)],
        input="untrusted-sensitive-input",
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert reply.returncode == 1
    assert "PermissionError" in reply.stdout
    assert "untrusted-sensitive-input" not in reply.stdout + reply.stderr
    assert "attachment_admission_fenced" not in reply.stdout
