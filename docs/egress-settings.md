# Project egress settings

This component implements settings contracts and preferences persistence, not packet enforcement
or live egress acceptance. Project ownership is checked by ads before invoking preferences.

Preferences exposes GET/PUT/DELETE `/v1/projects/{project_id}/egress-settings`. GET of a missing
row returns 404, never a synthetic revision-zero policy. PUT returns 200 with `revision` and
`settings`; initial persisted revision is 1 and every successful save increments it atomically,
including identical saves. Rules retain their order. DELETE is idempotent (204) for project
creation compensation. Project IDs are lifetime identities, never reused after deletion.

All calls require a verified preferences-audience JWT and caller `ads`. User operations require
role `user`. `ADS_PREFERENCES_ADS_SERVICE_SUBJECT` optionally identifies the native ADS service
account UUID: it may only GET project egress settings, not mutate settings or access models,
even if that account is accidentally assigned a user role. An unset subject grants no service
GET exception. No service subject selects project ownership. Background manager binding checks
belong to the ads delivery component, not this database.

Domains accept ASCII DNS A-labels (case folded), `*`, or exactly one whole leftmost wildcard.
Unicode input and trailing dots are rejected rather than implicitly reinterpreted. Ports are
integers 1–65535. The method enum is `any`, GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE,
PATCH; CONNECT does not override the independent generic-tunnel ban. Paths use explicit patterns;
omission means no path restriction. Optional case flags cannot be null. Settings are immutable
typed snapshots. Canonical defaults preserve rule order and do not perform ruleset analysis.

Limits: 1,024 rules, 256 paths per rule, 8,192 characters per pattern, 253 characters per domain.
The data plane must separately enforce normalized-path, DNS, address, protocol and identity rules.
An allowed policy DTO is not a network permission by itself.

The new table is in the fresh-install bootstrap revision. There is intentionally no old-schema
upgrade/backfill. Deployment over an existing preferences schema requires the authorized scoped
reset procedure, including verified protected model-credential backup and automatic restoration.
Startup validates both model and project-egress tables and must fail closed on an old schema.
