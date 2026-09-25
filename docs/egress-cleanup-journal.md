# Retained pair cleanup journal

The existing cleanup capture now seals its complete ownership snapshot only
after the permanent creator fence and positive settlement of every original
writer. The journal lives on `sandbox_pair_intent`, not on the session or
`cleanup_work` foreign-key cascade. Fresh bootstrap creates the nullable JSON
column; no old-schema migration or adoption is introduced.

The first journal retains all captured resource UIDs, committed payloads,
dispatch evidence, original cleanup targets and sticky workspace retention.
Retries do not replace these with a new claim's targets. Session/work deletion
does not erase the journal. Subsequent snapshot construction uses this original
ownership, validates it against the retained generation ledger and rejects
identity or payload drift. A captured inflight marker remains unchanged even
when its original writer subsequently settled normally; a separately captured
UID fills an unbound creator slot without rewriting the creator ledger.

An optional original node-capture report is committed against the same owned
cleanup claim and exact four captured Pod UIDs. The caller must supply fresh
trusted node placement and an authenticated node-owner response. Repeated exact
reports are idempotent; changed boot, inventory, scope or identity cannot replace
the first report. Its digest is not authentication or freshness.

The journal itself is not node transport, release proof or deletion authority.
The composed normal, recovery and registry-driven orphan paths must commit it
before ordered teardown, honor its retained targets and sticky retention
disposition, and obtain positive runtime/storage release rather than interpreting
API absence. Unsupported or contradictory partial inventories remain blocked.

The subsequent ordered runtime stage now extends this same journal with
`ipc_placement`, `ipc_capture` and `ipc_release`. Placement records the exact
Pod UID, application node and resource version; the separate IPC capture binds
namespace, sandbox/generation, Pod and volume UIDs, boot and protected inventory
digest. Its positive observation must match the original capture, including
boot identity. These fields survive session/work-row removal, are immutable
once recorded and are revalidated before reuse. They do not authorize storage
reclamation or final generation retirement. Production node delivery and the
actual IPC node observer are separate implemented components, not proven by
these manager tests. See [authenticated delivery](egress-node-delivery.md) and
[IPC storage](egress-ipc-storage.md) for their proof boundaries.
