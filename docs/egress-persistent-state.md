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
There is no migration or adoption of an existing installation. Before activation,
implement exact immutable Secret/Block-PVC publication and observation, retained
writer settlement, immutable cleanup snapshots and positive single-owner transfer.
The wrapping-key delivery into Kata must not assume shared filesystem Secret mounts.
Actual encrypted SQLite use, DNSSEC/ECH records and data-plane behavior belong to
their later component; this ledger does not claim those features or live acceptance.
