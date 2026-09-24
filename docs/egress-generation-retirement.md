# Generation retirement and retained ownership receipts

`PairRetirementRepository` accepts only the original, still-owned cleanup claim.
It seals the original writers, reloads the retained typed proof journal, and
requires runtime, storage, controls, credentials and topics to reach their
authorized terminal dispositions. Idle additionally requires complete original
workspace/state/key identities and retained topics.

The retirement row contains the full nonsecret journal and its consistency
digest. It has no session/work foreign-key cascade and no update/delete API.
The original intent remains permanently creator-fenced and gains `retired_at`.
The partial unique sandbox index applies only to active attachment generations;
it never requires deleting historical intent to admit another generation.
Old creators cannot settle or reenter a retired generation.

## Exclusive transfer

`PairTransferRepository` consumes one positively retired idle generation exactly
once. Session and workspace locks arbitrate competing claims. A new attachment
generation inherits only the original workspace UID, persistent state UUID,
state volume UID, wrapping-custody UID/fingerprint and retained topics. It does
not regenerate keys, substitute missing storage, or rewrite creator provenance.
The unique predecessor constraint prevents competing successors.

Inherited settled workspace/topic entries refer to the original completed
publication, with that provenance recorded in the transfer receipt. They are
not permission to dispatch another create. Fresh CA consumer clones, controls,
private processes, relay credentials/inputs and IPC resources remain new
generation obligations.

The SQL-only `finish_idle` operation can commit retirement, detached workspace
state and stopped session state atomically. Legacy admission remains rejected;
the explicit paired claim path validates the preceding retirement and retained
identity. Missing or altered proofs remain blockers.

## Current integration boundary

Repository-level positive, rollback, claim-loss, tamper, concurrent-resume and
session/work-loss tests use real PostgreSQL. Final lifecycle caller routing,
external retained-resource validation before attachment, expiry/reap arbitration
and destructive recovery completion remain separate integration work. The
existing unconditional final paired completion guard has not been removed
merely because these repository contracts are available. This is not live
runtime validation or whole-slice acceptance.
