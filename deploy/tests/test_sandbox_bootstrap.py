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
        "--rootfs",
        "/session/rootfs",
        "/bin/sleep",
        "infinity",
    ]
    assert "/dev/fuse" not in script
    assert script.index("\ngreen2\n") < script.index("\n/usr/local/sbin/ads-session-device-check\n")
    assert script.index("podman_cmd start dev-sandbox") < script.index(
        "touch /run/ads-sandbox-ready"
    )
    assert "exec capsh --drop=cap_sys_admin" in script
