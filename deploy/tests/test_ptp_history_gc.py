# ruff: noqa: F811
from __future__ import annotations

import fcntl
import os
import time
from pathlib import Path

import pytest
from test_ptp_attachment import inputs, kernel, plugin  # noqa: F401


def touch(path, mtime):
    os.close(os.open(path, os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC, 0o600))
    os.utime(path, (mtime, mtime))


@pytest.fixture
def aged(plugin, inputs, kernel):
    config, env, _ = inputs
    req, _, active, _, _, _ = kernel
    plugin.perform(config, env)  # Real ADD creates attempt + lock + active journal.
    old = time.time() - 8 * 86400
    root = Path(config["stateDir"])
    foreign = {
        "fence": root / "retired-somegen.json",
        "pin": root / "partial-release-somegen.json",
    }
    for path in foreign.values():
        touch(path, old)
    keys = {"expired": "e" * 64, "held": "f" * 64, "fresh": "0" * 64}
    for key in keys.values():
        touch(root / ("attempt-" + key + ".json"), old if key != keys["fresh"] else time.time())
        touch(root / (key + ".lock"), old if key != keys["fresh"] else time.time())
    pend = root / ".pending-old"
    touch(pend, old)
    held = os.open(root / (keys["held"] + ".lock"), os.O_RDONLY | os.O_CLOEXEC)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    yield config, env, req, root, active, foreign, keys, pend, held
    fcntl.flock(held, fcntl.LOCK_UN)
    os.close(held)


def test_del_collects_only_expired_unlocked_history(plugin, inputs, kernel, aged):
    config, env, req, root, active, foreign, keys, pend, _held = aged
    env["CNI_COMMAND"] = "DEL"
    assert plugin.perform(config, env) is None
    assert not (root / ("attempt-" + keys["expired"] + ".json")).exists()
    assert not (root / (keys["expired"] + ".lock")).exists()
    assert not pend.exists()
    assert (root / ("attempt-" + keys["held"] + ".json")).exists()
    assert (root / (keys["held"] + ".lock")).exists()
    assert (root / ("attempt-" + keys["fresh"] + ".json")).exists()
    for path in foreign.values():
        assert path.exists()
    assert not active.exists()  # Normal DEL semantics; GC skipped the caller's own key first.


def test_idempotent_del_still_collects(plugin, inputs, kernel, aged):
    config, env, req, root, active, foreign, keys, pend, _held = aged
    env["CNI_COMMAND"] = "DEL"
    assert plugin.perform(config, env) is None
    assert plugin.perform(config, env) is None  # Second DEL takes the idempotent path.
    assert not (root / ("attempt-" + keys["expired"] + ".json")).exists()
    assert not pend.exists()
    assert (root / ("attempt-" + keys["held"] + ".json")).exists()


def test_released_lock_is_drained_by_next_del(plugin, inputs, kernel, aged):
    config, env, req, root, active, foreign, keys, pend, held = aged
    env["CNI_COMMAND"] = "DEL"
    assert plugin.perform(config, env) is None
    held_path = root / ("attempt-" + keys["held"] + ".json")
    assert held_path.exists()
    fcntl.flock(held, fcntl.LOCK_UN)
    assert plugin.perform(config, env) is None
    assert not held_path.exists()
    assert not (root / (keys["held"] + ".lock")).exists()
    for path in foreign.values():
        assert path.exists()
