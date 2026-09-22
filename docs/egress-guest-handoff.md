# Guest private NIC handoff

The existing no-network boot remains the default. The private mode is opt-in
through trusted Pod environment, not project policy or an inner-container input:
`ADS_SANDBOX_NETWORK_MODE=private`, canonical `ADS_ATTACHMENT_GENERATION`, and
explicit decimal `ADS_PRIVATE_MTU`. The paired manager integration must supply
these and add `NET_ADMIN` and `SYS_PTRACE` for this guest bootstrap only.
`SYS_PTRACE` permits opening `/proc/<pid>/ns/*` for the distinct mapped UID; it
does not belong in the untrusted inner container. That integration is not part
of this component.

Before mounting workspace storage, the immutable base helper checks the sole
non-loopback NIC, its generation-derived MAC, pair-local address, MTU, private
default gateway, lack of other routes/interfaces, and disabled IPv4 forwarding.
The no-network branch retains its original loopback/default-route/DNS checks.
Unknown modes fail rather than choosing a default.

Rootless Podman creates or starts `dev-sandbox` with the unchanged `nested-v1`
contract, `--network=none` and the existing delegated cgroup budget. No old
container is adopted automatically under a new contract, deleted or migrated.
The trusted helper obtains only a bounded, selected-field inspection through the
existing privilege-dropping Podman launcher. Inspection is not itself authority:
the actual PID must be alive, pinned with pidfd, own the expected rootless UID/GID
maps, and belong to the exact container cgroup under the delegated budget.
The held target network namespace must differ from the outer namespace and be
owned by the process's rootless user namespace. Repeat observations fence PID,
container and namespace replacement.

The helper moves `eth0` by an inherited namespace descriptor, then configures the
fixed private address and next-hop. It enters only the target network namespace,
never its mount/user namespace or filesystem root. Every privileged executable
comes from the immutable base with a fixed environment and bounded subprocess
deadline/output. There is no root execution of `/session/rootfs` software, no
root write through an inner filesystem path, and no caller-selected command.
The outer namespace becomes loopback-only. No new interface, bridge, NAT or
forwarding path is created. Inner IPv6 is disabled and IPv4 forwarding is off.

Resolver configuration is written through rootless Podman exec, as is existing
public CA trust installation and agent initialization. Readiness is written only
after these steps succeed. Final pause drops `SYS_ADMIN`, `NET_ADMIN` and `SYS_PTRACE`.
The untrusted inner environment can subsequently change its private routes; the
external relay/egress boundary remains the authority, not guest-side cooperation.

A root-only exclusive marker makes handoff one-shot per outer boot. Failure
leaves readiness absent and never rolls the NIC into a new/replaced process.
Recovery recreates the guest Pod/VM and its attachment; it does not retry the
half-completed operation in place. The marker is ephemeral in `/run`, not on the
persistent workspace.

## Proof boundary

Unit tests cover configuration, topology, identity/namespace changes, descriptor
use, command bounds, one-shot failure, and boot ordering. GitHub Actions exercises
the real transfer function into a subordinate-ID-mapped rootless Linux network
namespace, with a private TCP roundtrip, outer loopback-only check and duplicate
denial. This native kernel test does not impersonate a full Podman/CRI or Kata
boot: actual Podman inspection/cgroup shape, full guest trust/agent initialization,
workspace persistence and nested Podman remain explicit published-image lab
gates. Manager full-pair lifecycle and application policy acceptance are separate.
