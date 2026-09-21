# Nested Podman runtime contract

This source implements the successful isolated Kata canary combination, not a
claim that a new published image has passed startup/resume or full MCP acceptance.
Build the base and golden images through GitHub Actions. Do not build them in the
test lab. No migration of existing rootfs data is performed by this change.

## Operator prerequisites

Provision a separate containerd Kata handler and RuntimeClass, normally
`kata-qemu-ads`. Clone the known-good Kata handler, changing its CRI
`cgroup_writable` setting to `true`. Keep the other handlers unchanged.
Preserve the RuntimeClass scheduling restrictions and overhead, and the existing
Kata QEMU/runtime-rs configuration:

```toml
[runtime]
internetworking_model = "none"
disable_new_netns = false
```

The isolation contract remains block-backed guest and session storage
(EROFS/virtio-blk, `shared_fs=none`), no guest uplink, no service-account token in
the guest and no extra accessible disks. This proc preparation is not supported
on an ordinary host-kernel container or a shared-filesystem guest.
Keep the existing guest-agent seccomp policy; do not disable Podman's seccomp.
The canary used Kata's `disable_guest_seccomp=true`, independently of the enabled
outer and nested Podman seccomp filters.

After checking the handler and guest configuration, annotate its RuntimeClass
with `ads.io/runtime-contract: nested-v1`. Helm checks this attestation and the
configured CPU/memory headroom; it cannot read containerd or Kata TOML through
the Kubernetes API. No node configuration is applied by this chart.

The guest must expose a private, writable cgroup-v2 mount with `nsdelegate`,
CPU/memory/PID controllers, and finite enclosing CPU/memory limits. Unsupported
layouts fail before Ready. The proc allowlist matches the tested Kata layout:
`interrupts`, `keys`, `timer_list`, `bus`, `fs`, `irq`, and `sys`. The trusted
bootstrap validates all backing mounts and rejects propagation or unexpected
submounts before unmounting any of them.

## Startup and execution

```text
Kata container cgroup (CRI-owned, finite CPU/memory limits)
+-- init                         trusted guest/bootstrap/exec processes
+-- ads-budget                   root-owned hard limits; zero swap
    +-- podman                   UID 1000 delegated subtree
        +-- launcher             rootless Podman management processes
        +-- outer container      private cgroup namespace
            +-- agent            agent process and subsequent exec
            +-- nested container(s)
```

Only delegated directories and files listed in `/sys/kernel/cgroup/delegate`
are handed to UID 1000. The kernel list must contain `cgroup.procs`,
`cgroup.threads`, and `cgroup.subtree_control`; it may also contain
`memory.oom.group` and `memory.reclaim`. Only listed, present files are
delegated, and unknown names fail before mutation. Ancestor budget controls
remain guest-root-owned.
The exec helper joins PID 1's cgroup namespace, moves itself into `launcher`,
then executes Podman through `runuser`. Caller arguments never become a
guest-root shell command. Shell/Python stdin, exit status and IPC PID tracking
retain the existing wrapper contract.

The outer container stays rootless and non-privileged, uses `--network=none`,
native overlay without `/dev/fuse`, and default seccomp. Its targeted unmask
options are separate arguments for `/sys/fs/cgroup`, `/proc/acpi`, `/proc/keys`,
`/proc/timer_list`, `/proc/bus`, `/proc/fs`, `/proc/irq`, and `/proc/sys`.
No `unmask=ALL`, `/dev/mqueue` exception, or seccomp-unconfined option is needed.

The golden rootfs configures inner ranges `root:1:65536`, private IPC/PID/cgroup
namespaces, host network/UTS namespaces, enabled cgroups and cgroupfs management.
The container starts its preinstalled `/bin/sleep infinity`. The base-owned
`ads-agent-init` is then streamed over stdin to `podman exec -i dev-sandbox python3 -`;
no initialization helper script is stored in the writable session rootfs.
It moves the agent into a leaf before enabling controllers. Initialization must
succeed, then readiness checks that leaf and controller availability, on both
create and resume. If the agent removes or breaks required inner software,
startup fails without readiness; it does not repair those modifications.
No setuid helper permission restoration is introduced.

## Egress CA trust input

When the manager supplies `ADS_CA_ATTEMPT`, bootstrap requires the separate
`/dev/ads-ca-public` clone. The trusted helper checks the kernel read-only flag,
mounts ext4 with `ro,noload,nodev,nosuid,noexec`, checks filesystem read-only state,
and validates the committed Job attempt, certificate fingerprint, CA constraints
and exact expiry through the shared commons verifier. It mounts before the
unchanged disk inventory check, so the declared public source is already
kernel-claimed. A device without an attempt is rejected; absent inputs retain
the isolated component-test path until manager clone integration.

Only `trusted-egress-ca.pem` is streamed to `podman exec` for installation under
`/usr/local/share/ca-certificates/ads-egress.crt`. Neither parent chains nor the
egress-only company bundle are imported. Writable-rootfs software is executed
inside the rootless container, never through guest-root chroot. Trust failure
prevents initialization/readiness on both create and resume. The private-key
source is never an input to this helper and must never be attached to the guest.

The base image build context is now the repository root so it copies the exact
shared verifier rather than maintaining a fork. GitHub Actions remains the only
image builder. Unit tests do not establish kernel read-only or live trust proof.

## Existing sessions and proof gates

An existing `dev-sandbox` without label `ads.io/runtime-contract=nested-v1`
is rejected; it is not automatically removed, recreated or upgraded. A new
runtime also requires the corrected inner configuration and preinstalled Python
and sleep in the golden rootfs, but no ADS initialization script there.
Retained older sessions need a separately reviewed migration plan. Compatible
resume does not recursively chown their rootfs, preserving nested storage ownership.

Unit tests simulate proc/cgroup files and verify fail-closed decisions,
delegation ownership, placement order, configuration and namespace separation.
They do not emulate kernel permission enforcement. After publishing and before
rollout, run an isolated canary with the built images and prove:

- Fresh startup, shell/Python execution and repeated exec.
- Nested execution with default private IPC and seccomp mode 2.
- Namespace separation, no FUSE, no routes, and bounded nested cgroups.
- Negative attempts to raise the ancestor budget or migrate to guest siblings.
- Container restart and Pod recreation/resume on the same disposable disk,
  retaining files and correct UID/GID ownership.
- Missing/broken inner Python or sleep fails startup without readiness or repair.
- Exit-code propagation, timeout/abort behavior, and full authenticated MCP.

Do not mark those live acceptance gates passed from a successful image build.
