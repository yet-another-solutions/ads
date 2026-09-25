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

## Production completion and preattachment validation

Normal idle now calls `finish_idle` only after the ordered runtime, storage and
resource stages. The resulting stopped session is eligible only for explicit
paired admission. Before its first new create, the builder verifies the exact
retained workspace/state PVCs, original PV/CSI identities, wrapping custody and
absence of contradictory current users. A one-way transfer validation receipt
precedes every new compute dispatch. A restarted creator reuses that receipt
and its own exact resources rather than rejecting its own newly attached Pods.
Historical clone sources need not survive an ordinary retained resume.

Destructive recovery retires every condemned original generation and removes
only proof-covered workspace records in the same SQL transaction as the fresh
claim. The fresh sandbox and state identities differ deliberately. Missing
proof rolls back the entire terminal transition; no new publication begins.
Never-dispatched interim recovery identities are admitted only in configured
paired mode, where all create-capable operations first require a durable
generation under the session claim.

## Retained expiry and work loss

`PairDisposal` is a non-cascading, irreversible whole-lifetime disposal claim.
Session/workspace locks arbitrate it against transfer, and its existence
permanently excludes a successor. It does not invent another attachment
generation or change the preceding retirement journal. It reobserves the
original Block capture, retains exact PVC/PV/CSI identities and records actual
protected reclamation before deleting wrapping custody and topics. Finishing
expiry removes the workspace record and ends the stable sandbox identity.

`PairRegistry` inventories the durable generation and disposal records. Exact
read adapters enumerate all committed Pods, controls, storage, keys and inputs;
no Secret list/watch permission is needed. The registry reconstructs lost
cleanup work under current valid ownership. A lost session can become a true
orphan only after excluding every independent session/PVC/recovery owner.
Retained orphan cleanup first records an immutable `orphan-retained` retirement,
then uses the separate disposal claim. Paired markers without a durable ledger
are quarantined, never interpreted as legacy orphan deletion authority.

Queue-priority renewal for ambiguous orphan work is scheduling only. It cannot
settle an original write, change a UID or prove release, and avoids letting a
permanently blocked orphan monopolize a bounded worker batch.

## Interrupted retained resume

A successor that fails before attaching a consumer cannot call the inherited
volume globally “never mounted.” Its `retired-inherited-csi` capture references
the predecessor retirement digest and original backing identities. If that
backing was previously mounted, a fresh observation of the original Block
inventory is required. A changed boot, missing original inventory or changed
binding blocks destruction. Original never-mounted provenance is preserved
explicitly instead of manufacturing a new node inventory.

These are code/test contracts, not claims of live runtime validation. Slice
acceptance additionally requires the cumulative local and exact-head CI gates.
