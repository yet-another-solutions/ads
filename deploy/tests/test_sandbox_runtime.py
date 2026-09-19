"""Trusted setup tests use a fake cgroup tree; live kernel proof stays a canary gate."""

import importlib.machinery
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, service, script):
    loader = importlib.machinery.SourceFileLoader(
        name, str(ROOT / "services" / service / "scripts" / script)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


runtime = load("sandbox_runtime", "ads-sandbox-base", "ads-sandbox-runtime")
agent = load("agent_init", "ads-sandbox-base", "ads-agent-init")


@pytest.fixture
def tree(tmp_path, monkeypatch):
    cg, proc = tmp_path / "cg", tmp_path / "proc"
    cg.mkdir()
    (proc / "self").mkdir(parents=True)
    (proc / "1/ns").mkdir(parents=True)
    (proc / "1/ns/cgroup").touch()
    (proc / "self/cgroup").write_text("0::/\n")
    for name, value in {
        "cpu.max": "100000 100000",
        "memory.max": str(1536 * 1024**2),
        "cgroup.procs": "1\n",
        "cgroup.controllers": "cpu memory pids",
    }.items():
        (cg / name).write_text(value)
    monkeypatch.setattr(runtime, "CG", cg)
    monkeypatch.setattr(runtime, "PROC", proc)
    for key in runtime.BUDGET_DEFAULTS:
        monkeypatch.delenv(f"ADS_SANDBOX_{key}", raising=False)
    return cg, proc


def test_budget_values_and_guest_headroom(tree):
    assert runtime.limits() == {
        "cpu.max": "75000 100000",
        "memory.max": "805306368",
        "memory.swap.max": "0",
        "pids.max": "256",
        "cgroup.max.depth": "8",
        "cgroup.max.descendants": "32",
    }


@pytest.mark.parametrize(
    "key,value",
    [
        ("PIDS", "0"),
        ("PIDS", "-1"),
        ("PIDS", "1.5"),
        ("PIDS", str(2**63)),
        ("PIDS", "true"),
        ("CPU_MILLIS", "1000"),
        ("MEMORY_BYTES", "1610612736"),
        ("MEMORY_BYTES", "4097"),
    ],
)
def test_invalid_or_unbounded_budget_fails(tree, monkeypatch, key, value):
    monkeypatch.setenv(f"ADS_SANDBOX_{key}", value)
    with pytest.raises(RuntimeError):
        runtime.limits()


@pytest.mark.parametrize("file,value", [("cpu.max", "max 100000"), ("memory.max", "max")])
def test_enclosing_limits_required(tree, file, value):
    (tree[0] / file).write_text(value)
    with pytest.raises(RuntimeError, match="mandatory"):
        runtime.limits()


@pytest.mark.parametrize(
    "options,super_options,kind,valid",
    [
        ("rw", "rw,nsdelegate", "cgroup2", True),
        ("ro", "rw,nsdelegate", "cgroup2", False),
        ("rw", "rw", "cgroup2", False),
        ("rw", "rw,nsdelegate", "cgroup", False),
    ],
)
def test_cgroup_mount_contract(tree, monkeypatch, options, super_options, kind, valid):
    cg = tree[0]
    monkeypatch.setattr(
        runtime,
        "mounts",
        lambda: {"1": f"1 0 0:1 / {cg} {options} - {kind} cgroup {super_options}"},
    )
    if valid:
        runtime.check_cgroup_mount()
    else:
        with pytest.raises(RuntimeError, match="writable cgroup v2"):
            runtime.check_cgroup_mount()


def proc_mounts():
    return {
        str(index): f"{index} 0 0:1 {root} {target} ro - {kind} none ro"
        for index, (target, (kind, root)) in enumerate(runtime.PROC_MASKS.items(), 1)
    }


def test_exact_proc_unmounts_and_no_seccomp_change(monkeypatch):
    table = proc_mounts()
    monkeypatch.setattr(runtime, "mounts", lambda: dict(table))
    calls = []

    def unmount(args, check):
        calls.append(args)
        assert check
        key = next(key for key, value in table.items() if value.split()[4] == args[-1])
        del table[key]

    monkeypatch.setattr(runtime.subprocess, "run", unmount)
    runtime.prepare_proc()
    assert calls == [["umount", "--", path] for path in sorted(runtime.PROC_MASKS)]
    assert not table


@pytest.mark.parametrize("change", ["extra", "missing", "backing", "shared", "duplicate"])
def test_unexpected_proc_layout_rejected_before_mutation(monkeypatch, change):
    table = proc_mounts()
    if change == "extra":
        table["8"] = "8 0 0:1 / /proc/foreign rw - tmpfs none rw"
    elif change == "missing":
        del table["1"]
    elif change == "backing":
        table["1"] = table["1"].replace("/null", "/foreign")
    elif change == "shared":
        table["1"] = table["1"].replace(" - ", " shared:9 - ")
    else:
        table["8"] = table["1"].replace("1 0 ", "8 0 ")
    monkeypatch.setattr(runtime, "mounts", lambda: table)
    run = Mock()
    monkeypatch.setattr(runtime.subprocess, "run", run)
    with pytest.raises(RuntimeError):
        runtime.prepare_proc()
    run.assert_not_called()


def test_proc_mount_race_fails_closed(monkeypatch):
    table = proc_mounts()
    monkeypatch.setattr(runtime, "mounts", Mock(side_effect=[table, {}]))
    run = Mock()
    monkeypatch.setattr(runtime.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="changed"):
        runtime.prepare_proc()
    run.assert_not_called()


@pytest.mark.parametrize("root,same", [(False, True), (True, False)])
def test_namespace_or_identity_mismatch_fails(monkeypatch, root, same):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0 if root else 1000)
    monkeypatch.setattr(runtime.os, "readlink", lambda path: "ns" if same else str(path))
    with pytest.raises(RuntimeError):
        runtime.check_namespaces()


@pytest.mark.parametrize(
    "optional",
    [(), ("memory.oom.group",), ("memory.reclaim",), ("memory.oom.group", "memory.reclaim")],
)
def test_delegation_keeps_budget_controls_root_owned(tree, monkeypatch, optional):
    cg, _ = tree
    monkeypatch.setattr(runtime, "check_namespaces", lambda: None)
    monkeypatch.setattr(runtime, "check_cgroup_mount", lambda: None)
    monkeypatch.setattr(runtime, "prepare_proc", lambda: None)
    monkeypatch.setattr(runtime.os, "readlink", lambda path: "ns")
    monkeypatch.setattr(
        runtime.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1000, pw_gid=1000)
    )
    original_read, original_write, original_mkdir = Path.read_text, Path.write_text, Path.mkdir

    def read(path, *args, **kwargs):
        if str(path) == "/sys/kernel/cgroup/delegate":
            return "\n".join(
                ("cgroup.procs", "cgroup.threads", "cgroup.subtree_control", *optional)
            )
        return original_read(path, *args, **kwargs)

    def write(path, data, *args, **kwargs):
        result = original_write(path, data, *args, **kwargs)
        if path == cg / "init/cgroup.procs":
            original_write(cg / "cgroup.procs", "")
        return result

    def mkdir(path, *args, **kwargs):
        original_mkdir(path, *args, **kwargs)
        if path.is_relative_to(cg):
            original_write(path / "cgroup.controllers", "cpu memory pids")
            for name in (
                "cgroup.procs",
                "cgroup.threads",
                "cgroup.subtree_control",
                "memory.oom.group",
                "memory.reclaim",
            ):
                original_write(path / name, "")

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(Path, "write_text", write)
    monkeypatch.setattr(Path, "mkdir", mkdir)
    chown = Mock()
    monkeypatch.setattr(runtime.os, "chown", chown)
    runtime.prepare()
    assert (cg / "ads-budget/cpu.max").read_text() == "75000 100000"
    assert (cg / "ads-budget/memory.swap.max").read_text() == "0"
    assert not (cg / "cgroup.procs").read_text()
    expected = {
        directory / name if name else directory
        for directory in (cg / "ads-budget/podman", cg / "ads-budget/podman/launcher")
        for name in ("", "cgroup.procs", "cgroup.threads", "cgroup.subtree_control", *optional)
    }
    assert {call.args[0] for call in chown.call_args_list} == expected
    assert all(call.args[1:] == (1000, 1000) for call in chown.call_args_list)
    with pytest.raises(RuntimeError, match="already exists"):
        runtime.prepare()


@pytest.mark.parametrize(
    "delegate_files",
    [
        "",
        "cgroup.procs",
        "cgroup.procs cgroup.threads",
        "cgroup.procs cgroup.subtree_control",
        "cgroup.threads cgroup.subtree_control",
        *[
            f"cgroup.procs cgroup.threads cgroup.subtree_control {extra}"
            for extra in (
                "cpu.max",
                "memory.max",
                "memory.swap.max",
                "pids.max",
                "cgroup.max.depth",
                "cgroup.max.descendants",
                "../cgroup.procs",
                "/etc/passwd",
                "future.control",
            )
        ],
    ],
)
def test_invalid_delegate_list_rejected_before_mutation(tree, monkeypatch, delegate_files):
    cg, _ = tree
    monkeypatch.setattr(runtime, "check_namespaces", lambda: None)
    monkeypatch.setattr(runtime, "check_cgroup_mount", lambda: None)
    monkeypatch.setattr(runtime.os, "readlink", lambda path: "ns")
    original_read = Path.read_text

    def read(path, *args, **kwargs):
        if str(path) == "/sys/kernel/cgroup/delegate":
            return delegate_files
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    prepare_proc, chown = Mock(), Mock()
    monkeypatch.setattr(runtime, "prepare_proc", prepare_proc)
    monkeypatch.setattr(runtime.os, "chown", chown)
    with pytest.raises(RuntimeError, match="kernel delegation"):
        runtime.prepare()
    prepare_proc.assert_not_called()
    chown.assert_not_called()
    assert not (cg / "ads-budget").exists()
    assert not (cg / "init").exists()
    assert (cg / "cgroup.procs").read_text() == "1\n"


def test_exec_placement_precedes_privilege_drop_and_preserves_arguments(tree, monkeypatch):
    cg, _ = tree
    leaf = cg / "ads-budget/podman/launcher"
    leaf.mkdir(parents=True)
    (leaf / "cgroup.procs").touch()
    monkeypatch.setattr(runtime, "check_namespaces", lambda: None)
    monkeypatch.setattr(runtime, "check_cgroup_mount", lambda: None)
    events = []
    monkeypatch.setattr(runtime.os, "setns", lambda fd, flags: events.append("namespace"))

    def execute(binary, args):
        assert (leaf / "cgroup.procs").read_text() == str(runtime.os.getpid())
        events.append("drop")
        assert binary == "runuser"
        assert args[:6] == ["runuser", "-u", "podman", "--", "env", "HOME=/home/podman"]
        assert "--cgroup-manager=cgroupfs" in args
        assert args[-5:] == ["exec", "-i", "dev-sandbox", "sh", "literal; not guest-root shell"]

    monkeypatch.setattr(runtime.os, "execvp", execute)
    runtime.podman(["exec", "-i", "dev-sandbox", "sh", "literal; not guest-root shell"])
    assert events == ["namespace", "drop"]


def test_agent_leaf_preparation_and_resume(tree, monkeypatch):
    cg, _ = tree
    monkeypatch.setattr(agent, "CG", cg)
    original_read, original_write = Path.read_text, Path.write_text

    def read(path, *args, **kwargs):
        if str(path) in ("/etc/subuid", "/etc/subgid"):
            return "root:1:65536\n"
        if str(path) == "/proc/self/status":
            return "Seccomp:\t2\n"
        return original_read(path, *args, **kwargs)

    def write(path, data, *args, **kwargs):
        result = original_write(path, data, *args, **kwargs)
        if path == cg / "agent/cgroup.procs":
            original_write(cg / "cgroup.procs", "")
        return result

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(Path, "write_text", write)
    agent.prepare()
    assert (cg / "agent/cgroup.procs").read_text() == "1"
    assert (cg / "cgroup.subtree_control").read_text() == "+cpu +memory +pids"
    agent.prepare()


@pytest.mark.parametrize("range_value,seccomp", [("root:100000:65536", "2"), ("root:1:65536", "0")])
def test_agent_refuses_old_ranges_or_disabled_seccomp(monkeypatch, range_value, seccomp):
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path: f"Seccomp:\t{seccomp}\n" if str(path) == "/proc/self/status" else range_value,
    )
    with pytest.raises(RuntimeError):
        agent.prepare()


def test_missing_controller_does_not_enable_partial_delegation(tree):
    cg, _ = tree
    (cg / "cgroup.controllers").write_text("cpu memory")
    with pytest.raises(RuntimeError, match="controllers are required"):
        runtime.enable(cg)
    assert not (cg / "cgroup.subtree_control").exists()


def test_exec_without_prepared_delegation_never_drops_into_podman(tree, monkeypatch):
    monkeypatch.setattr(runtime, "check_namespaces", lambda: None)
    monkeypatch.setattr(runtime, "check_cgroup_mount", lambda: None)
    monkeypatch.setattr(runtime.os, "setns", lambda *_: None)
    execute = Mock()
    monkeypatch.setattr(runtime.os, "execvp", execute)
    with pytest.raises(RuntimeError, match="delegation is not ready"):
        runtime.podman(["exec", "dev-sandbox", "true"])
    execute.assert_not_called()


def test_runtime_cli_rejects_other_root_commands(monkeypatch):
    monkeypatch.setattr(runtime.sys, "argv", ["ads-sandbox-runtime", "sh", "-c", "anything"])
    with pytest.raises(RuntimeError, match="usage"):
        runtime.main()
