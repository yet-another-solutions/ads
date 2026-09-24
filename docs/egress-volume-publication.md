# Tracked paired workspace and CA clones

This internal slice-19 component replaces neither the existing golden/CA source
services nor the ordinary lifecycle state machine. It supplies the missing
per-pair clone-writer evidence needed before production paired creation can use
fresh workspace and three CA-consumer PVCs.

## Publication contract

The existing pair intent owns a fixed `volume_resources` map for workspace,
guest public CA, egress public CA and egress private CA. Each entry contains its
complete nonsecret manifest, original source names/UIDs/Job identity and maximum
requested/capacity size, workspace UUID and exact transition, dispatch state and
observed clone UID. No keys or arbitrary API metadata enter this payload.

Existing golden and CA services provide released, identity-verified sources.
The adapter revalidates committed sources before creation and around observation;
both CA sources must remain the same complete initialization pair. CSI still
references a source by name: any detected replacement blocks binding and later
compute rather than adopting a potentially wrong clone.

The current creating claim and settled control identities authorize a single
reservation, committed before API I/O. The original retained invocation alone
settles after normal return. A retry only observes; lost replies, cancellation,
failed settlement and absence cannot reissue creates or clear inflight markers.
Workspace UID binding updates both session and existing PVC-lifetime row
atomically. CA source association commits before the first CA clone write, and
clone UIDs bind individually without replacing an existing anchor.

This is a fresh-publication path, not legacy adoption or persistent-state
transfer. Untracked pre-existing UID bindings are rejected. No compute,
topics, readiness, deletion or runtime release is performed here.

## Cleanup and defaults

Cleanup snapshots retain clone payloads and capture late exact UIDs only after
the permanent creator fence under the current existing cleanup/recovery claim.
The observation is metadata-only and never calls source-initialization services.
Deleting or content-drifted owned clones remain obligations; absence never
forgets known UIDs or supplies release/reclamation evidence.

API quantity canonicalization, assigned PV name and the equivalent local
dataSourceRef are accepted. Different source references, namespace expansion,
capacity changes, owner references, labels or replacement UIDs fail closed.
The existing fresh initial schema gets one column, with no backfill or migration.

## Validation note

The same feature also makes the pre-existing MCP GC-age test deterministic after
PR119 merge CI exposed a wall-clock race. Its real PostgreSQL advisory leader
exclusion and scheduler remain; every original assertion is retained and the
strict exact-retention-cutoff assertion is added. No production GC behavior
or timeout changes.

Full paired creation, ordered teardown, positive runtime/storage release,
retirement/transfer and credential-preserving reset remain required. This
component is not full live integration acceptance.
