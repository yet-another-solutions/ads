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

This component introduces no node transport, resource deletion, positive runtime
release, storage reclamation, retirement or retained-state transfer. Existing
normal, recovery and orphan runtime-release guards remain closed. Unsupported
partial node inventories remain blocked. Later ordered teardown must commit this
journal before deletion, honor its retained targets and retention disposition,
and obtain positive release evidence rather than interpreting API absence.
