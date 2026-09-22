# Private attachment component

`services/ads-ptp-tools/ads-ptp` is the node-side Python CNI component, shipped
inside the existing CI-built tooling image. It is not installed by this PR.
It adds one veth endpoint to the VM runtime namespace and the other to the
attested relay's private bridge. It never places that bridge in the host or
ordinary CNI namespace, runs cluster IPAM, delegates to Cilium, enables
forwarding, or installs NAT. It assigns only the attested pair-local IPv4
address to the VM endpoint. Guest setup adds the private default gateway/DNS;
egress setup preserves upstream routing and DNS without a private default route.
The relay bridge and local relay veth remain unnumbered.

Containerd requires an IP configuration on its default interface
([CRI setupPodNetwork](https://raw.githubusercontent.com/containerd/containerd/2976f38ccbfcda5ef1364d63d60b0a304e4bf94a/internal/cri/server/sandbox_run.go)).
An address-free result would pass an isolated L2 test but fail CRI setup.
The plugin therefore configures and returns the actual isolated pair address,
not a dummy cluster address. Kata/inner-Podman transfer of this configured NIC
remains a separate integration gate.

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
device/inode identities, effective private MTU, pair-local address and gateway.
Addresses must be canonical RFC1918 IPv4 host addresses on a /24; guest gateway
must be another host in that same subnet, while egress gateway must be null.
These inputs are platform-owned, never project policy. The attestor must establish
these from current Kubernetes/CRI observations, reject terminating/replaced or
foreign-node objects, and verify the private namespace belongs to that exact
relay runtime. A root-authored record is authorization, not proof of those
facts by itself. This PR does not claim to implement the attestor.

Both namespace references are opened and verified using nsfs type and
device/inode. Held descriptors, not a later PID lookup, address kernel
operations. Host, VM, relay-private and relay-transport namespace identities
must all differ. The unnumbered bridge must bear the exact relay UID/generation
alias and contain only its VXLAN port before attachment. Guest ADD rejects
another interface or a previous CNI result. Egress preserves the ordinary
upstream plugin's result and adds only its private endpoint address.

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
their observed indices. A nonzero numeric link group derived from that same
identity is set atomically on both veth ends at creation; aliases are then set
explicitly before attachment/up. The kernel applies IFLA_GROUP during creation
but IFLA_IFALIAS only on updates
([rtnetlink implementation](https://raw.githubusercontent.com/torvalds/linux/v6.11/net/core/rtnetlink.c)).
For incomplete ADD only, DEL tolerates a missing alias if the original exact
namespace, interface kind and creation group still match. It never tolerates
a foreign nonempty alias or missing/replaced group. This is an ownership fence
against lifecycle mistakes, not protection against trusted host-root forgery.
Failed/partial ADD retains intent for DEL; it never
pretends setup succeeded. A repeated ADD is rejected until DEL.

CHECK requires the recorded private interface in `prevResult`, the unchanged
binding, the expected bridge membership, exact aliases/indices, operational
MTU/link state, private IP and guest default gateway. It does not equate a
WireGuard handshake with CNI readiness.
Unrelated result entries may be changed by later upstream configuration.

DEL uses the original journal, not a refreshed binding that could point to a
replacement relay. It validates both surviving links before deleting either.
Absent original namespaces/interfaces are harmless, while a reused path or
foreign alias/index fails closed. No namespace, bridge, VXLAN, WireGuard,
upstream interface or unrelated link is deleted. Successful DEL removes the
journal; repeated DEL succeeds. Tiny per-tuple lock files remain intentionally.
Kernel peer removal after namespace destruction can race an explicit delete;
an operation error is accepted only after positive interface-absence rechecks.
A surviving original or replacement link retains the failure and journal.

## Proof boundary

Unit tests use a fake kernel to cover input rejection, protected records,
partial ADD, lifecycle idempotency and replacement safety. The existing
tooling-image CI job additionally runs real ADD/CHECK/DEL, actual pair-local
address/default-route inspection, replacement denial and missing-namespace cleanup. No lab build is
authorized or required.

Remaining gates: trusted node attestor, relay runtime integration, scoped
runtime/CNI installation, actual Kata TAP/TC handoff, inner Podman NIC transfer,
concurrent pair isolation, ingress/broadcast limits, manager ownership and
fault recovery. No production attachment or full egress acceptance is claimed.
