from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOT = ROOT / "services/ads-sandbox-base/scripts/ads-sandbox-boot"


def test_guest_boot_uses_device_free_isolated_outer_container():
    script = BOOT.read_text()
    subprocess.run(["bash", "-n", str(BOOT)], check=True)
    create = next(
        shlex.split(line)
        for line in script.splitlines()
        if line.strip().startswith("podman_cmd create ")
    )
    assert create == [
        "podman_cmd",
        "create",
        "--name",
        "dev-sandbox",
        "--network=none",
        "--cgroupns=private",
        "--cgroup-parent=/ads-budget/podman",
        "--label",
        "ads.io/runtime-contract=nested-v1",
        "${unmask[@]}",
        "--rootfs",
        "/session/rootfs",
        "/usr/local/sbin/ads-agent-init",
    ]
    assert "/dev/fuse" not in script
    assert script.index("\ngreen2\n") < script.index("\n/usr/local/sbin/ads-session-device-check\n")
    assert script.index("podman_cmd start dev-sandbox") < script.index(
        "touch /run/ads-sandbox-ready"
    )
    assert "exec capsh --drop=cap_sys_admin" in script
    assert "seccomp=unconfined" not in script
    assert "unmask=ALL" not in script
    assert 'unmask+=(--security-opt "unmask=$path")' in script
    assert "explicit migration required" in script
    assert script.index("cgroup initialization failed") < script.index(
        "touch /run/ads-sandbox-ready"
    )


def test_exec_uses_same_trusted_placement_without_changing_contract():
    script = BOOT.with_name("ads-session-exec").read_text()
    subprocess.run(["bash", "-n", str(BOOT.with_name("ads-session-exec"))], check=True)
    assert "ads-sandbox-runtime podman exec -i -w /workspace dev-sandbox" in script
    assert 'podman_exec /bin/bash --noprofile --norc -c "$1"' in script
    assert "podman_exec python3 -u -" in script
    assert "trap clear_pid EXIT" in script
    assert 'printf \'%s\\n\' "$$" >"$PID_FILE"' in script


def test_inner_image_uses_private_ipc_and_mapped_ranges():
    inner = (ROOT / "services/ads-sandbox-golden/Containerfile.inner").read_text()
    assert inner.count("root:1:65536") == 2
    assert "root:100000:" not in inner
    for setting in (
        'netns = "host"',
        'utsns = "host"',
        'ipcns = "private"',
        'pidns = "private"',
        'cgroupns = "private"',
        'cgroups = "enabled"',
        'cgroup_manager = "cgroupfs"',
    ):
        assert setting in inner
