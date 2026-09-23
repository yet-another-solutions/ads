# Persistent egress state reservation

This internal manager ledger reserves a sandbox-lifetime state identity separately
from a pair attachment generation. It is not connected to production creation,
readiness, cleanup or retirement yet. No Kubernetes resources are created by it.

## Ownership and custody

`sandbox_egress_state` stores the session/project/sandbox identity, initial creator
generation and claim, namespace, explicit capacity, an opaque state UUID, a SHA-256
commitment to a random 256-bit wrapping key, and separate key/volume dispatch and
UID evidence. There is no session/pair foreign-key cascade and no private-key column.
The UUID, rather than the creator generation, is the eventual persistent resource
identity. The wrapping key belongs to separate immutable custody, never the state PVC.

Reservations lock the current session, pair and then state. Only the transaction
that first reserves custody generates private bytes; callers MUST commit before
using those transient bytes for an external write. Rollback means no dispatch.
Every subsequent caller/restart receives only public evidence and may only observe
the original reserved object. A crash between reservation and dispatch intentionally
remains ambiguous; absence does not authorize key regeneration.

The key resource starts inflight. Only the original invocation's normal return can
record settlement, even after claim loss or creator fencing. An observed UID never
settles a write. Volume dispatch is one-shot and requires settled, UID-bound key
custody. UIDs cannot be replaced. Size changes, stale claims, changed provenance and
corrupt evidence fail closed. No capacity default is chosen by this component.

Retained state blocks legacy session admission even if the session and pair rows
are lost. State is not an API-presence or runtime-release proof. There is no deletion,
rotation, ownership-transfer or generation-reuse API; later generations cannot
adopt the record without the subsequent fenced lifecycle implementation.

## Integration boundary

The fresh-install initial schema and startup table verification include the ledger.
There is no migration or adoption of an existing installation. A committed pair
anchor distinguishes first reservation from loss of an already-reserved state row;
cleanup snapshots retain that anchor and creator fencing rejects any drift.

The internal publisher creates the immutable wrapping Secret and separate fresh
Block/RWO/sandbox-block PVC exactly once after their reservations commit. Resource
names depend on the persistent state UUID, not a new attachment/process identity.
Exact labels bind session/project/sandbox, initial creator, state format and role;
the volume additionally binds the observed wrapping-custody UID. No controller
owner references, clone source, selected foreign disk or secret material in the
volume specification is permitted. Observation checks custody before and after
volume reads, accepts only exact capacity with API quantity canonicalization,
and never recreates a missing bound resource. Original writer tasks survive
caller cancellation to record normal-return settlement. Lost/failed replies stay
inflight, even if restart binds an observed UID. A custody settlement race can
fail a concurrent caller closed; a later attempt may observe committed completion.

No production publisher caller, ready transition or teardown is enabled.
Cleanup now captures the full nonsecret persistent reservation under the existing
lifecycle claim and retains it independently of subsequent API observations.
Before each named Secret/PVC metadata read, the permanent pair creator fence and
exact immutable state scope are revalidated. Every observed UID commits separately
after another claim/scope check. Missing observations never erase known UIDs or
settle dispatch. Deleting or content-drifted owned resources remain cleanup
obligations; this path does not decode Secret data or inspect PVC contents.
Only original writer settlement may advance live SQL inflight evidence, and it
does not rewrite the earlier cleanup snapshot. No absence/ready/release/retirement
verdict, deletes or ownership transfer are introduced by capture.

Before activation, complete positive single-owner transfer and ordered teardown.
The fixed egress Pod constructor uses named required SecretKeyRefs, not shared
filesystem Secret mounts. Wrapping custody format v2 stores canonical ASCII base64
in `wrapping.b64` (inside Kubernetes' outer data encoding), preserving the exact
original 256-bit key. The volume format stays v1. Raw v1 custody is rejected, not
converted or regenerated; no production publisher has been activated.
The constructor has only three block devices: writable persistent state and the
two read-only CA consumer clones. TLS uses separate named SecretKeyRefs. It emits
no private values, Kubernetes token, guest workspace, shared volume, fake health,
restart/adoption permission or arbitrary Pod customization. A distinct explicit
Kata RuntimeClass, digest-pinned image and bounded resources are required.
This is a pure specification, not a runnable egress bootstrap or publication.
The eventual runtime must decode and verify the key fingerprint, validate block
identity, safely mount existing state, preload TLS, enforce private/upstream
separation and prove actual health before admission.
Actual encrypted SQLite use, DNSSEC/ECH records and data-plane behavior belong to
their later component; this ledger does not claim those features or live acceptance.
