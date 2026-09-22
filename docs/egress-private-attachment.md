# Private L2 attachment component

`services/ads-ptp-tools/ads-ptp` is the node-side Python CNI component, shipped
inside the existing CI-built tooling image. It is not installed by this PR.
It adds one veth endpoint to the VM runtime namespace and the other to the
attested relay's private bridge. It never places that bridge in the host or
ordinary CNI namespace, runs IPAM, delegates to Cilium, assigns an IP, adds a
route, enables forwarding, or installs NAT. Trusted VM bootstrap will assign
the pair-local addresses after Kata transports the private L2 interface.

## Trust and prerequisites

A trusted node attestor must publish a root-owned mode-0600 binding under a
root-owned mode-0700 binding directory. This publisher is a subsequent
integration component, not a success-returning fallback. Missing attestation
fails ADD. Relays and guests must never write the binding/state directories.
Neither receives a host runtime socket, general host filesystem, Kubernetes
credential or node CNI authority from this component.

The exact record fields are checked by `binding()`: VM Pod UID, sandbox UUID,
attachment generation, role, interface/network names, current local relay Pod
UID and runtime sandbox ID, private and transport namespace paths plus nsfs
device/inode identities, and effective private MTU. The attestor must establish
these from current Kubernetes/CRI observations, reject terminating/replaced or
foreign-node objects, and verify the private namespace belongs to that exact
relay runtime. A root-authored record is authorization, not proof of those
facts by itself. This PR does not claim to implement the attestor.

Both namespace references are opened and verified using nsfs type and
device/inode. Held descriptors, not a later PID lookup, address kernel
operations. Host, VM, relay-private and relay-transport namespace identities
must all differ. The unnumbered bridge must bear the exact relay UID/generation
alias and contain only its VXLAN port before attachment. Guest ADD rejects
another interface or a previous CNI result. Egress may preserve the ordinary
upstream plugin's result, but private attachment adds no IP or routing entry.

`iproute2` accepts absolute namespace paths, including inherited
`/proc/self/fd/N` paths, rather than only mutable PID references
([namespace implementation](https://raw.githubusercontent.com/iproute2/iproute2/main/lib/namespace.c)).
The kernel CI job verifies this with real namespaces and veth operations.

## Lifecycle

The [CNI specification](https://www.cni.dev/docs/spec/) defines ADD, CHECK, DEL,
VERSION, attachment identity, result handling and repeated/missing-namespace
cleanup. This component advertises CNI 1.0.0. The network/runtime/interface
tuple selects a locked journal; intent is fsynced before link creation.
Links carry a generation/Pod/runtime-derived alias, and completion persists
their observed indices. Failed/partial ADD retains intent for DEL; it never
pretends setup succeeded. A repeated ADD is rejected until DEL.

CHECK requires the recorded private interface in `prevResult`, the unchanged
binding, the expected bridge membership, exact aliases/indices and operational
MTU/link state. It does not equate a WireGuard handshake with CNI readiness.
Unrelated result entries may be changed by later upstream configuration.

DEL uses the original journal, not a refreshed binding that could point to a
replacement relay. It validates both surviving links before deleting either.
Absent original namespaces/interfaces are harmless, while a reused path or
foreign alias/index fails closed. No namespace, bridge, VXLAN, WireGuard,
upstream interface or unrelated link is deleted. Successful DEL removes the
journal; repeated DEL succeeds. Tiny per-tuple lock files remain intentionally.

## Proof boundary

Unit tests use a fake kernel to cover input rejection, protected records,
partial ADD, lifecycle idempotency and replacement safety. The existing
tooling-image CI job additionally runs real ADD/CHECK/DEL, no-IP/no-route
inspection, replacement denial and missing-namespace cleanup. No lab build is
authorized or required.

Remaining gates: trusted node attestor, relay runtime integration, scoped
runtime/CNI installation, actual Kata TAP/TC handoff, inner Podman NIC transfer,
concurrent pair isolation, ingress/broadcast limits, manager ownership and
fault recovery. No production attachment or full egress acceptance is claimed.
