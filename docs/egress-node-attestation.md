# Node-side private attachment attestation

`ads-ptp-attest` is imported by the node CNI before every production ADD and
CHECK. It is not a daemon, relay API or guest tool. It has no network mutation
operations. A missing or failed live observation never falls back to an older
binding record. DEL remains independent of API availability and uses only the
original attachment journal.

## Authority and installation

Install the three related node files (`ads-ptp`, `ads-ptp-attest` and their Python
interpreter) from the CI-built tooling artifact, not a lab build. The relay
executable belongs in its ordinary container, not a node service. The node CNI
configuration supplies `attestorConfig`, the path to a private root-owned JSON
file with exactly these keys:

```json
{
  "node": "<observed local Kubernetes node name>",
  "namespace": "<manager-owned sandbox namespace>",
  "network": "<private CNI network name>",
  "kubeconfig": "<absolute protected read-only API kubeconfig path>",
  "kubectl": "<absolute root-owned kubectl executable>",
  "crictl": "<absolute root-owned crictl executable>",
  "cri_endpoint": "unix://<absolute local containerd socket path>",
  "relay_image": "<exact immutable published relay image reference>",
  "relay_image_id": "sha256:<observed runtime image digest>",
  "relay_container": "<manager-owned relay container name>",
  "guest_runtime": "<dedicated private-only Kata RuntimeClass>",
  "egress_runtime": "<dedicated upstream-plus-private Kata RuntimeClass>",
  "transport_mtu": 1450
}
```

The MTU above is an example, not a platform default: supply the observed path
MTU. The image ID must be the runtime's verified image reference digest, not an
unverified tag or a guessed manifest type. The attestor deliberately supports
the containerd runtime integration only; a different CRI needs an explicit
tested adapter rather than permissive parsing.

The API identity requires only get/list Pods in the sandbox namespace. Do not
reuse administrator credentials or grant Secret access, exec, writes, or
cluster-wide wildcard rights. TLS verification is forced on each kubectl call.
The local CRI socket and node `/proc` are trusted node authority and must not be
mounted into either relay or either VM. No attestation listener is exposed.

## Current-object and process checks

The VM must have the exact requested Pod UID, expected private RuntimeClass,
node and namespace, no termination timestamp or host namespaces, and canonical
manager-owned session/sandbox/project/generation labels. The matching local
relay must be unique, share all four identities, use the ordinary runtime and
the exact configured image/container, and report a running containerd ID.
An older terminating duplicate is not silently preferred or ignored.

CRI then binds the relay Pod UID to one ready sandbox, the exact running
container ID, expected sandbox ID, namespace and immutable image digest.
`pidfd_open`, process start ticks and held nsfs descriptors fence process and
namespace reuse. Missing PID-descriptor support is an error, not a weaker
PID-only fallback. The container and sandbox must share the ordinary transport
namespace; the private namespace must be distinct.

The relay's protected completed journal must name the exact Pod, sandbox,
generation and both namespace identities. Both Kubernetes and CRI observations
are repeated after reading the private namespace. The CNI subsequently performs
its own held-descriptor bridge/link checks before network effects. The VM CRI
sandbox need not yet exist: CNI is part of its creation, so requiring it would
create a bootstrap dependency cycle.

## Persistence and failure behavior

Successful observation atomically replaces the private root-owned binding.
The configuration supplies no project-controlled address or namespace path:
pair-local endpoints follow the adopted fixed isolated topology, while
namespace paths come from observed relay processes. A 20-second whole
observation budget and bounded individual API/CRI commands prevent indefinite
CNI work. Command output is private temporary data, size-checked before JSON
loading; stderr and runtime specs are never logged.

The production CLI requires `attestorConfig` for ADD/CHECK. Static records remain
available only to the in-process native kernel fixture API; they are not a
production command-line bypass. Failed refresh leaves any previous record
unusable by that invocation. CHECK still compares the newly observed binding
with its original journal; a replacement relay cannot retarget an existing
attachment. Cleanup does not use a newly observed identity.

## Proof boundary

Tests cover pair selection, replacement/termination/ambiguity, node/namespace/
runtime/image mismatches, CRI ownership, journal and namespace mismatch,
process-exit/reuse fences, forced TLS and stale-record rejection. The existing
two-relay kernel fixture additionally exercises real PID descriptors against
both running relay processes.

Live scoped API/RBAC and CRI observations, installation on the sandbox worker,
actual Kata TAP/TC and inner-Podman NIC handoff, and manager-driven pair recovery
remain separate gates. A synthetic Kubernetes/CRI fixture is not proof of those
live contracts.
