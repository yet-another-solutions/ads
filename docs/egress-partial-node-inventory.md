# Partial private-runtime node inventory

`ads-ptp-partial` captures nonempty, exact subsets of the private pair without
changing the original full four-Pod `ads-node-release-v1` contract. Its separate
`ads-partial-release-v1` report names each original role and Pod UID. It cannot
stand in for IPC, storage release or final generation retirement.

## Trusted scope and original history

The authenticated manager channel has two new fixed operations:
`partial-capture` and `partial-observe`. They accept only the existing immutable
pair scope and a nonempty map of `guest`, `egress`, `guest-relay` and
`egress-relay` to their original UIDs. No request can select executables,
configuration paths, CRI endpoints, commands or credentials. Existing dedicated
mTLS, pinned manager identity, nonce/request-digest correlation, deadlines,
response limits and node-specific origins remain unchanged.

Capture first durably fences CNI admission, then runs under that same generation
lock. It requires the original assigned local Pods; a missing API object is not
an empty runtime. Namespace, sandbox, generation, native/VM runtime role and
controller-free ownership must match. An unexpected local private-generation
member blocks capture. IPC on the same physical node is outside this inventory
and still needs its separate original IPC proof.

- **VM attempts:** Protected pre-effect ADD history supplies original runtime
  IDs and positively observed namespace device/inode pairs, including attempts
  that failed before attestation. Requests, attachment keys, boot identities and
  interface roles are revalidated. An admitted binding must also match the
  original pair and relay UID. Every currently observed CRI VM runtime must be
  covered by that history. A missing original namespace slot is not fabricated.
- **Relays:** Fresh exact Kubernetes/CRI/container/image/PID observations and
  process pins bind a completed running relay setup. Capture records its
  private and transport namespaces and actual host peer. The protected setup
  journal and runtime are checked again before releasing the process pins.
- **Persistence:** The root-owned private `partial-release-<generation>.json`
  contains the first role inventory and original attempt-record digests.
  Atomic file/directory fsync precedes the report. Retry reasserts durability
  without recapturing or adopting replacements; changed boot, scope or UID map
  is rejected.

API and attempt observations are repeated before committing a new capture.
The digest binds this protected inventory but is not authentication; only a
fresh response through the authenticated node-owner channel is accepted.

## Positive release observation

The original capture is required. The helper revalidates the durable admission
fence, boot identity and every captured attempt digest before and after the
bounded release scan. Changed or missing history is a blocker, not permission
to reconstruct the inventory after deletion.

The shared node scanner checks original/generation Pods, ready or unknown CRI
sandboxes, live/created/unknown containers, active CNI journals, original or
reused host peers, every process/task namespace, held namespace descriptors and
namespace bind mounts. API/CRI observations are repeated after the scan. Only
all-clear counts yield runtime release; observations never retire the
generation. Positively identified kernel threads and zombies have no live
userspace references; incomplete or unreadable userspace observations fail.

## Supported and still-unfinished boundaries

This supports a positively captured one-sided pair, a completed live relay-only
prefix, and a VM whose original failed/pre-attestation ADD history exists even
when its CRI record was later collected. It does not infer no CNI ADD from an
empty directory. Missing attempt history, an unobserved original namespace,
incomplete/lost relay setup history and node reboot remain blocked.

This component supplies the real helper and authenticated delivery contract.
Manager lifecycle composition of partial, never-scheduled and never-dispatched
roles remains a separate required integration step. Storage capture/release,
reclamation, exact disposal, final retirement and all remaining slice-19
acceptance obligations are not claimed complete.

## Verification

The component suite exercises actual protected record persistence, immutable
retry, original map/scope/boot refusal, pre-attestation history, one-sided and
relay-only capture, each observed release blocker and changed history. External
API/CRI/process-pin boundaries are faked explicitly in those unit tests.
Channel tests reject substituted roles, UIDs, capture bindings, report phases
and envelope correlation. The tooling-image CI smoke also captures a real
namespace into protected attempt history and requires the partial report to
remain blocked by its real bind mount, process and held descriptor until every
reference is removed. This is a kernel component gate, not a live lab claim.
