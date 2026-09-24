# ruff: noqa: F811
from __future__ import annotations

import contextlib
import os
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest
from test_ptp_attachment import inputs, kernel, plugin  # noqa: F401


def attempt_path(config, req):
    return Path(config["stateDir"]) / ("attempt-" + req["key"] + ".json")


def test_missing_attestation_preserves_original_namespace_before_any_effect(plugin, inputs, kernel):
    config, env, attestation = inputs
    req, _, active, _, _, calls = kernel
    Path(config["bindingDir"], attestation["pod_uid"] + ".json").unlink()
    with pytest.raises(FileNotFoundError):
        plugin.perform(config, env)
    saved = plugin.read_record(attempt_path(config, req))
    assert saved == {
        "schema": "ads-ptp-attempt-v1",
        "request": req,
        "boot_id": plugin.boot_identity(),
        "vm_identity": [1, 10],
        "binding": None,
    }
    assert not active.exists() and not calls
    env["CNI_COMMAND"] = "DEL"
    assert plugin.perform(config, env) is None
    assert plugin.read_record(attempt_path(config, req)) == saved


def test_namespace_lookup_failure_keeps_attempt_without_fabricating_identity(
    plugin, inputs, kernel
):
    config, env, _ = inputs
    req, _, active, _, paths, calls = kernel
    paths.pop(env["CNI_NETNS"])
    with pytest.raises(FileNotFoundError):
        plugin.perform(config, env)
    saved = plugin.read_record(attempt_path(config, req))
    assert saved["vm_identity"] is None and saved["binding"] is None
    assert saved["request"] == req and not active.exists() and not calls
    # A retry before any namespace was observed may fill that single null slot.
    paths[env["CNI_NETNS"]] = 10
    plugin.perform(config, env)
    assert plugin.read_record(attempt_path(config, req))["vm_identity"] == [1, 10]


def test_del_keeps_immutable_history_and_check_does_not_rewrite_it(plugin, inputs, kernel):
    config, env, binding = inputs
    req = kernel[0]
    config["prevResult"] = plugin.perform(config, env)
    path = attempt_path(config, req)
    original = path.read_bytes()
    saved = plugin.read_record(path)
    assert saved["binding"] == binding
    assert path.stat().st_mode & 0o777 == 0o600
    env["CNI_COMMAND"] = "CHECK"
    plugin.perform(config, env)
    assert path.read_bytes() == original
    env.update(CNI_COMMAND="DEL", CNI_NETNS="", CNI_ARGS="")
    plugin.perform(config, env)
    plugin.perform(config, env)
    assert not kernel[2].exists()
    assert path.read_bytes() == original


@pytest.mark.parametrize("stage", ["request", "namespace", "binding"])
def test_attempt_durability_failure_prevents_network_effects(
    plugin, inputs, kernel, monkeypatch, stage
):
    config, env, _ = inputs
    original = plugin.save_record
    count = 0

    def save(path, value):
        nonlocal count
        if path.name.startswith("attempt-"):
            count += 1
            if count == {"request": 1, "namespace": 2, "binding": 3}[stage]:
                raise OSError("fsync unavailable")
        return original(path, value)

    monkeypatch.setattr(plugin, "save_record", save)
    with pytest.raises(OSError, match="fsync"):
        plugin.perform(config, env)
    assert not kernel[2].exists() and not kernel[-1]


@pytest.mark.parametrize("changed", ["request", "boot", "namespace", "binding"])
def test_retry_cannot_replace_original_attempt(plugin, inputs, kernel, monkeypatch, changed):
    config, env, binding = inputs
    plugin.perform(config, env)
    path = attempt_path(config, kernel[0])
    original = path.read_bytes()
    env["CNI_COMMAND"] = "DEL"
    plugin.perform(config, env)
    kernel[-1].clear()
    env["CNI_COMMAND"] = "ADD"
    if changed == "request":
        env["CNI_ARGS"] = "K8S_POD_UID=" + str(uuid4())
    elif changed == "boot":
        monkeypatch.setattr(plugin, "boot_identity", lambda: str(uuid4()))
    elif changed == "namespace":
        kernel[4][env["CNI_NETNS"]] = 11
    else:
        binding["generation"] = str(uuid4())
        plugin.save_record(Path(config["bindingDir"], binding["pod_uid"] + ".json"), binding)
    with pytest.raises(ValueError, match="original"):
        plugin.perform(config, env)
    assert path.read_bytes() == original
    assert not kernel[2].exists() and not kernel[-1]


def test_attestation_race_cannot_retarget_original_namespace(plugin, inputs, kernel, monkeypatch):
    config, env, _ = inputs
    original = plugin.binding

    def changed(*args):
        result = original(*args)
        kernel[4][env["CNI_NETNS"]] = 11
        return result

    monkeypatch.setattr(plugin, "binding", changed)
    with pytest.raises(ValueError, match="namespace replaced"):
        plugin.perform(config, env)
    assert not kernel[2].exists() and not kernel[-1]


@pytest.mark.parametrize("fault", ["shape", "identity", "admitted", "mode", "symlink"])
def test_corrupt_or_unprotected_attempt_is_never_overwritten(
    plugin, inputs, kernel, fault, tmp_path
):
    config, env, _ = inputs
    path, saved = plugin.capture_attempt(Path(config["stateDir"]), kernel[0])
    if fault == "shape":
        saved["extra"] = True
    elif fault == "identity":
        saved["vm_identity"] = [True, 1]
    elif fault == "admitted":
        saved.update(vm_identity=None, binding=deepcopy(inputs[2]))
    plugin.save_record(path, saved)
    if fault == "mode":
        path.chmod(0o644)
    elif fault == "symlink":
        target = tmp_path / "other"
        path.rename(target)
        path.symlink_to(target)
    original = path.read_bytes()
    with pytest.raises((ValueError, OSError)):
        plugin.perform(config, env)
    assert path.read_bytes() == original
    assert not kernel[2].exists() and not kernel[-1]


def test_missing_attempt_is_not_backfilled_from_active_attachment(plugin, inputs, kernel):
    config, env, _ = inputs
    plugin.perform(config, env)
    attempt_path(config, kernel[0]).unlink()
    before = kernel[2].read_bytes()
    with pytest.raises(ValueError, match="missing original attempt history"):
        plugin.perform(config, env)
    assert kernel[2].read_bytes() == before
    assert not attempt_path(config, kernel[0]).exists()


def test_busy_attachment_lock_does_not_create_or_update_attempt(plugin, inputs, kernel):
    config, env, _ = inputs
    req = kernel[0]
    lock = Path(config["stateDir"], req["key"] + ".lock")
    fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        plugin.fcntl.flock(fd, plugin.fcntl.LOCK_EX | plugin.fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            plugin.perform(config, env)
        assert not attempt_path(config, req).exists()
    finally:
        os.close(fd)


def test_namespace_inspection_happens_only_after_durable_request(
    plugin, inputs, kernel, monkeypatch
):
    config, env, _ = inputs
    original = plugin.namespace
    req = kernel[0]

    @contextlib.contextmanager
    def namespace(path, *args, **kwargs):
        assert plugin.read_record(attempt_path(config, req))["request"] == req
        with original(path, *args, **kwargs) as fd:
            yield fd

    monkeypatch.setattr(plugin, "namespace", namespace)
    plugin.perform(config, env)
