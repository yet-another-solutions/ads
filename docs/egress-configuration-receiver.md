# Paired egress configuration receiver

The `ads-sandbox-egress` workspace package supplies the control receiver and
atomic policy snapshot store. It is not yet a deployable data-plane image or
listener. There is deliberately no production fake health provider, no permissive
bootstrap, and no success claim for traffic inspection in this component.

## Atomic installation

One process owns one `PolicyStore`, one fresh boot UUID and one immutable current
snapshot reference. None means unconfigured/deny-all, not a persisted revision
zero. The data plane must use this same store and capture a snapshot once for
each new exchange; updates never mutate captured active-exchange policy.

Structural validation and semantic-default canonicalization precede a serialized
compare/swap. New revisions atomically replace the entire immutable snapshot.
Equal revision/equal canonical settings returns 200 without replacing it. Equal
revision/different settings returns 409 `revision_conflict`. Older revisions
return the exact commons 409 `stale_revision` envelope. A closed store returns
503 and cannot be mutated. Failed validation preserves the prior snapshot.

`PUT /configuration` verifies the configured commons issuer/audience and native
IPC subject plus `azp=ads-sandbox-ipc`, then checks immutable project equality.
There is no JWT or snapshot persistence here. The private control listener and
pair-restricted CNI ingress remain required runtime/deployment work; a shared
IPC service subject is not per-Pod identity.

`GET /ping` returns boot UUID and `healthy`. It depends on bounded injected local
enforcement/helper health and update capability, never an applied revision or
Internet reachability. The full runtime must provide that real health port and
preload its control TLS keys/trust before starting the HTTPS server.

## Proof boundary

Tests exercise signed JWT denial, strict DTO validation, atomic monotonicity,
idempotent replay, semantic defaults, active snapshot immutability, shutdown,
health deadlines, and fresh process UUID/unconfigured state. A cross-component
test wires the actual ADS publisher, IPC verified message boundary, IPC HTTPS
adapter and egress receiver using an ASGI socket substitute. It proves fan-out
payload installation, revision fencing and fresh apply credentials after restart.
Broker transport, token endpoint and local helper health are fixtures.

Full data-plane runtime bootstrap, shared CA/identity volumes, local NGINX helper,
TLS/ECH/DNSSEC enforcement, private transport, scoped live identity and network
denials remain their own implementation and live-acceptance gates. No package
import or control endpoint proof substitutes for those gates.
