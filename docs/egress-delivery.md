# Egress delivery and fencing

## Implemented IPC component

`TokenExchange.exchange_service(audience)` obtains a fresh client-credentials
token and immediately performs own-token STE as that same client. It never uses
the bound user holder, caches a bearer, persists one, or substitutes delegated
identity on failure. The receiving boundary checks issuer/audience through the
common verifier and caller plus the configured native service-account subject.

`ads.sandbox.egress.config` uses commons tagged `config-request` and `config-update`
DTOs. Authorization uses the existing Kafka `authorization` header convention.
Updates carry a project ID and persisted revision/settings snapshot. Each IPC
has its own sandbox-keyed consumer group. The config consumer subscribes, starts
and completes seek-to-end before IPC publishes its fresh service-origin request.
Configuration processing is independent of execution and ping consumers.

Manager pair injection supplies `ADS_SANDBOX_IPC_PROJECT_ID`, `EGRESS_URL`,
`LOCAL_RELAY_HEALTH_URL`, `PEER_RELAY_HEALTH_URL`, and `ADS_SERVICE_SUBJECT`.
Partial environment configuration fails startup. Absent pair configuration is
only the pre-existing no-NIC v1 path, not a permitted paired-guest fallback.
The forthcoming pair provisioning component must always inject all fields.

IPC stores only `{project_id, revision}` beneath `PID_DIRECTORY/egress/`.
Atomic replace and directory/file fsync preserve the floor. Existing PID cleanup
does not touch this subdirectory. Corrupt/mismatched records fail closed.
Installation evidence is separate and never restored from the revision file.
Payloads, JWTs, process UUIDs and the unhealthy latch are not checkpointed.

The first successful, expected-instance apply gates initial execution. Later
UUID changes clear installation evidence and trigger asynchronous reapplication,
not a new execution admission gate. Direct health checks query egress `/ping`
and both relay URLs; no relay Pod API reads are involved. Concurrent health
results are sequence-fenced. Application traffic may temporarily fail deny-all.

Every REST attempt mints a fresh IPC service-origin token. There are two attempts
total, including credential failures and timeouts. Exhaustion latches unhealthy
until process restart/recovery; good pings cannot clear it. Only a structurally
valid `409 error.code=stale_revision`, with the requested revision and a strictly
greater applied revision, is nonfatal. It is never installation evidence.
Unexpected-UUID success is consumed as a no-op, not retried as ordinary failure.

## Integration boundary

The ADS publisher, manager-owned project binding, paired egress receiver,
Helm injection, broker grants and live STE/CNI proof are separate remaining work
within the authenticated-delivery/pair/data-plane slices. This component is
wired into IPC but is not an integrated egress release or live acceptance proof.
