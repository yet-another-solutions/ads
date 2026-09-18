from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

import pytest

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
        "/bin/sleep",
        "infinity",
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


def test_initialization_code_is_packaged_only_in_base_image():
    base = (ROOT / "services/ads-sandbox-base/Containerfile").read_text()
    inner = (ROOT / "services/ads-sandbox-golden/Containerfile.inner").read_text()
    assert "COPY scripts/ads-agent-init /usr/local/sbin/ads-agent-init" in base
    assert "ads-agent-init" not in inner
    assert not (ROOT / "services/ads-sandbox-golden/scripts/ads-agent-init").exists()
    assert 'os.execv("/bin/sleep"' not in BOOT.with_name("ads-agent-init").read_text()


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("init_status", [0, 1, 127])
def test_base_owned_init_streamed_before_readiness(tmp_path, existing, init_status):
    """Exercise the real boot control flow with Podman mocked, without kernel mounts."""
    script = BOOT.read_text()
    startup = script[script.index("if podman_cmd container exists") : script.index("exec capsh")]
    startup = startup.replace(
        "/usr/local/sbin/ads-agent-init", shlex.quote(str(BOOT.with_name("ads-agent-init")))
    )
    harness = f"""
set -euo pipefail
fail() {{ echo "$*" >&2; exit 1; }}
chown() {{ :; }}
sleep() {{ :; }}
touch() {{ printf '%s\\n' "$*" >> ready; }}
podman_cmd() {{
  printf '%s\\n' "$*" >> calls
  case "$1" in
    container) return {0 if existing else 1};;
    inspect) echo nested-v1;;
    exec)
      if [[ "$2" == -i ]]; then
        cat > received-stdin
        return {init_status}
      fi
      ;;
  esac
}}
{startup}
"""
    result = subprocess.run(
        ["bash", "-c", harness], cwd=tmp_path, capture_output=True, text=True, check=False
    )
    calls = (tmp_path / "calls").read_text()
    assert (tmp_path / "received-stdin").read_bytes() == BOOT.with_name(
        "ads-agent-init"
    ).read_bytes()
    assert calls.index("start dev-sandbox") < calls.index("exec -i dev-sandbox python3 -")
    assert ("create --name dev-sandbox" in calls) is not existing
    if init_status:
        assert result.returncode != 0
        assert "agent cgroup initialization failed" in result.stderr
        assert not (tmp_path / "ready").exists()
        assert "exec dev-sandbox python3 -c" not in calls
    else:
        assert result.returncode == 0, result.stderr
        assert (tmp_path / "ready").read_text().strip() == "/run/ads-sandbox-ready"
        assert calls.index("exec -i dev-sandbox python3 -") < calls.index(
            "exec dev-sandbox python3 -c"
        )
