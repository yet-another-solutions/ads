# Retained pre-attestation CNI attempts

`ads-ptp` now commits a protected attempt before live attestation, namespace
inspection or any network effect. The existing active ADD journal begins
later, after attestation and kernel preflight. Keeping both distinguishes
an early failed attempt from a never-dispatched manager resource and from
an admitted attachment whose active journal was removed by DEL.

## Ordering

Under the existing per-attachment exclusive nonblocking lock:

- Persist the original ADD request and node boot identity as
  `attempt-<attachment-key>.json`, using atomic replacement and file/directory
  fsync. A namespace lookup failure leaves those original facts intact.
- Open the original runtime namespace and persist its nsfs device/inode before
  attestation. A retry may fill a previously unobserved null namespace slot,
  but may not substitute an already observed identity or boot.
- Obtain the existing fresh live Kubernetes/CRI/relay attestation and acquire
  the generation lock. An existing retirement fence still refuses admission.
- Persist the exact validated binding in the attempt immediately before
  calling ADD. A later attempt cannot replace that original binding.
- Reopen the runtime namespace with the captured identity and verify it again
  before the existing active-journal commit and first network effect.

The attempt is root-owned, mode 0600, under the existing protected state
directory. Reads reject symlinks, unsafe modes, unknown fields, conflicting
request/boot/namespace/binding identities and invalid namespace shapes.
Retries reassert durability without clearing original fields. An existing
active attachment without its attempt is not silently backfilled.

## Not release authority

DEL uses only its original active journal and still performs the existing exact
link/namespace checks. It never removes the attempt. CHECK does not invent or
rewrite attempt history. Neither a recorded request, a null binding nor the
absence of an active journal by itself proves runtime release, no future ADD,
storage release or generation retirement.

Generation binding is absent until real attestation and the admission-fence
check succeed. Cleanup must not infer it from an untrusted Pod label alone.
The retained attempt is preparation for positive partial-runtime inventory,
not a new manager success path or a replacement for the authenticated node
observer. Boot changes remain blocked; this record does not claim that a
reboot proves old storage/runtime release. No historical migration, history
garbage collection or later transport/data-plane acceptance is added here.

## Tests

Unit tests cover early attestation and namespace failures, durability failures,
late namespace replacement, protected-file corruption, changed original
identity, successful ADD/CHECK/DEL history retention and lock contention.
Existing fence/concurrency assertions are retained with namespace fixtures.
The tooling image's actual-kernel attachment smoke also verifies the
pre-attestation namespace record, immutable admitted binding and retained
history after DEL and namespace destruction.
