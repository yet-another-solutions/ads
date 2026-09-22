"""The guest shutdown contract; PID-namespace enforcement is also exercised in CI."""

import importlib.machinery
import importlib.util
import signal
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "services/ads-sandbox-base"
loader = importlib.machinery.SourceFileLoader(
    "sandbox_shutdown", str(BASE / "scripts/ads-sandbox-shutdown")
)
spec = importlib.util.spec_from_loader(loader.name, loader)
shutdown = importlib.util.module_from_spec(spec)
loader.exec_module(shutdown)


@pytest.fixture
def guest(monkeypatch):
    ready = Mock()
    ready.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
    monkeypatch.setattr(shutdown, "READY", ready)
    monkeypatch.setattr(shutdown.os, "getpid", lambda: 1)
    monkeypatch.setattr(shutdown.os, "geteuid", lambda: 0)
    kill = Mock()
    monkeypatch.setattr(shutdown.os, "kill", kill)
    monkeypatch.setattr(shutdown.signal, "signal", Mock())
    reap = Mock(return_value=True)
    monkeypatch.setattr(shutdown, "reap_children", reap)
    sync = Mock()
    monkeypatch.setattr(shutdown.subprocess, "run", sync)
    return ready, kill, reap, sync


@pytest.mark.parametrize("pid,uid", [(2, 0), (1, 1000), (23, 1000)])
def test_shutdown_rejects_non_guest_root_pid_one(guest, monkeypatch, pid, uid):
    monkeypatch.setattr(shutdown.os, "getpid", lambda: pid)
    monkeypatch.setattr(shutdown.os, "geteuid", lambda: uid)
    with pytest.raises(RuntimeError, match="root PID 1"):
        shutdown.shutdown()
    for mock in guest:
        assert not mock.mock_calls


@pytest.mark.parametrize(
    "mode,uid",
    [(stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o622, 0), (stat.S_IFREG | 0o600, 1000)],
)
def test_shutdown_rejects_untrusted_marker(guest, mode, uid):
    ready, kill, reap, sync = guest
    ready.lstat.return_value = SimpleNamespace(st_mode=mode, st_uid=uid)
    with pytest.raises(RuntimeError, match="readiness marker"):
        shutdown.shutdown()
    ready.unlink.assert_not_called()
    for mock in (kill, reap, sync):
        mock.assert_not_called()


def test_missing_marker_never_signals_or_flushes(guest):
    ready, kill, reap, sync = guest
    ready.lstat.side_effect = FileNotFoundError
    assert shutdown.main() == 1
    for mock in (kill, reap, sync):
        mock.assert_not_called()


@pytest.mark.parametrize("resistant", [False, True])
def test_close_admission_quiesce_then_filesystem_scoped_flush(guest, resistant):
    ready, kill, reap, sync = guest
    events = []
    ready.unlink.side_effect = lambda: events.append("closed")
    kill.side_effect = lambda pid, sig: events.append((pid, sig))
    reap.side_effect = [False, True] if resistant else [True]
    sync.side_effect = lambda *args, **kwargs: events.append("flushed")
    assert shutdown.main() == 0
    expected = ["closed", (-1, signal.SIGTERM)]
    if resistant:
        expected.append((-1, signal.SIGKILL))
    assert events == expected + ["flushed"]
    sync.assert_called_once_with(
        ["/usr/bin/sync", "-f", "/session"],
        check=True,
        timeout=10,
        stdin=subprocess.DEVNULL,
    )


def test_unreaped_processes_flush_but_cannot_report_success(guest):
    _, _, reap, sync = guest
    reap.return_value = False
    with pytest.raises(RuntimeError, match="did not quiesce"):
        shutdown.shutdown()
    assert reap.call_count == 2
    sync.assert_called_once()


@pytest.mark.parametrize(
    "error",
    [
        subprocess.TimeoutExpired("sync", 10),
        subprocess.CalledProcessError(1, "sync"),
        FileNotFoundError("sync"),
    ],
)
def test_flush_failures_cannot_report_success(guest, capsys, error):
    guest[3].side_effect = error
    assert shutdown.main() == 1
    assert "filesystem flushed" not in capsys.readouterr().out


def test_signal_accepts_no_children_not_permission_denial(guest):
    guest[1].side_effect = ProcessLookupError
    shutdown.signal_children(signal.SIGTERM)
    guest[1].side_effect = PermissionError
    with pytest.raises(PermissionError):
        shutdown.signal_children(signal.SIGTERM)


def test_reaping_adopted_children(monkeypatch):
    wait = Mock(side_effect=[(42, 0), (43, 0), ChildProcessError()])
    monkeypatch.setattr(shutdown.os, "waitpid", wait)
    assert shutdown.reap_children(2)
    assert wait.call_count == 3
    wait.assert_called_with(-1, shutdown.os.WNOHANG)


def test_reaping_deadline_is_bounded(monkeypatch):
    monkeypatch.setattr(shutdown.os, "waitpid", lambda *args: (0, 0))
    monkeypatch.setattr(shutdown.time, "monotonic", Mock(side_effect=[0, 1, 2]))
    sleep = Mock()
    monkeypatch.setattr(shutdown.time, "sleep", sleep)
    assert not shutdown.reap_children(2)
    sleep.assert_called_once_with(0.05)


def test_shutdown_is_base_owned_and_called_with_isolated_python():
    image = (BASE / "Containerfile").read_text()
    pause = (BASE / "scripts/pause.c").read_text()
    assert (
        "COPY services/ads-sandbox-base/scripts/ads-sandbox-shutdown "
        "/usr/local/sbin/ads-sandbox-shutdown"
    ) in image
    assert 'execl("/usr/bin/python3", "python3", "-I",' in pause
    assert '"/usr/local/sbin/ads-sandbox-shutdown"' in pause
    assert "sigsuspend(&previous)" in pause
    assert "sigprocmask(SIG_BLOCK" in pause
    assert (
        "ads-sandbox-shutdown"
        not in (ROOT / "services/ads-sandbox-golden/Containerfile.inner").read_text()
    )
