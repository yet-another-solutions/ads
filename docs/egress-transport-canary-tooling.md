# Disposable transport tooling

`ads-ptp-tools` is a diagnostic artifact built and published only by the existing
GitHub Actions matrices. It is not a production relay, CNI plugin or egress
enforcement image. Python, iproute2, WireGuard, nftables and bounded capture
tools travel in the image; the lab does not install or build project tooling.

The helper runs inside each disposable ordinary-runtime relay Pod. It needs
NET_ADMIN for links/firewalls and SYS_ADMIN for its own named network namespace
mounts, with seccomp/AppArmor allowances for those operations. It must not run
with hostNetwork, hostPID, hostIPC, a Kubernetes API token, a runtime socket,
host filesystem mounts or a shared host mount namespace. Mount `/run` as a
Pod-local memory emptyDir; use read-only image root and a separate writable
temporary directory. Neither capability is granted to an untrusted guest.
The helper mounts a fresh procfs only inside each `ip netns exec` child's
temporary mount namespace to set that private network namespace's sysctls;
the parent Pod's read-only proc masks and host mounts remain unchanged.

Supply exact Pod UID and manager/test-owned attachment generation UUID through
environment. `keygen` creates a new protected per-generation directory and
prints only the public key. Exchange public keys through the test orchestrator.
`configure` accepts one bounded exact-field JSON object on stdin with observed
transport MTU, runtime Service endpoint, private/tunnel addresses and ports.
The egress peer has no configured remote endpoint; it learns the authenticated
sender. No keys, hostnames or lab addresses are embedded in the helper.

WireGuard is created in the CNI namespace and moved to a new private namespace.
The unnumbered bridge contains only a local veth and fixed-peer VXLAN. A second
namespace stands in for the Kata endpoint for this bounded transport proof.
Private input and bridge forwarding are constrained with nftables, IP routing
is disabled, IPv6 is disabled where available, and there is no relay default
route or NAT. IPv4 encapsulation budgets are 60 bytes for WireGuard and a
further 50 bytes for Ethernet/VXLAN/UDP/IPv4. Both sides must use the smaller
observed path MTU; actual boundary probes remain mandatory.

Socket configuration creates the readiness record independently of handshake
success, avoiding a Service bootstrap cycle. That record explicitly reports
`tunnel_proven: false`. `inspect` emits public topology/counters only; no
WireGuard private-key dump is used. `cleanup` rejects mismatched identity,
refuses namespaces with active diagnostic processes or replaced namespace
device/inode identities, removes only names whose creation it recorded,
and verifies absence before deleting ephemeral key/state files. The
orchestrator must additionally delete and verify its Kubernetes namespace and
compare node/runtime baseline; helper success alone is not a cleanup verdict.

Unit tests verify command ordering, namespace ownership, topology validation
and credential handling without claiming a kernel datapath test. CI verifies
the built image's tools and performs real kernel setup/cleanup with the same
read-only-root/capability constraints, including IPv6 disablement and readiness
withdrawal when WireGuard is down. This is not a Service or link traffic proof.
The live acceptance matrix still requires real relay
Pods, the real UDP Service, captures with positive controls, Ethernet/TCP/UDP
integrity, negative identity/bypass/loss cases, MTU/idle/backend replacement and
complete cleanup. Cross-worker proof is explicitly deferred in the one-worker
lab; same-worker proof must be labelled as such. The production Kata NIC
attachment, relay health/authentication, lifecycle and application egress
contracts remain separate implementation work.
