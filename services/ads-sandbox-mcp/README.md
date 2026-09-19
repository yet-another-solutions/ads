# ads-sandbox-mcp

Slice 4 implements the authenticated sandbox tool door, not the manager or guest.
Run with `python -m ads_sandbox_mcp`. Litestar/uvicorn owns HTTPS and lifecycle;
the official `mcp==2.2.0` low-level `Server` owns MCP parsing, metadata validation,
discovery, dispatch and serialization. Dishka wires the registered tool callbacks,
execution service, watchdog, Kafka components, repository and cluster scheduler.

## Application composition

`create_app` assembles the provider graph, HTTP routes, authentication, and one
lifespan. `AppProvider` constructs the official SDK `Server` and owns the async
database engine through a yielding provider. Loop-bound beans are resolved only
inside the ASGI lifespan, and closing Dishka disposes each resolved engine even
when later construction or startup fails.

`McpRuntime` coordinates Kafka, cluster scheduler, and SDK session-manager startup,
then unwinds them in reverse order. The application stores one runtime reference;
it does not manually construct or dispose SDK/database dependencies. `http.py`
owns authentication, health routes, and the transparent disconnect adapter.
The SDK still owns all MCP parsing, dispatch, and serialization.

Tests retain the explicit `overrides` hook. `HarnessOverrides` supplies the
controlled execution service and external doubles, leaving SDK/runtime composition
real. The separate composition tests override external boundaries and verify the
production service/controller/provider graph, APP scope, startup/shutdown failures,
and disposal. Fixture-owned test engines are disposed by fixtures, not by the app.

## Boundaries

```text
ads-engine --HTTPS /mcp--> ADS authentication --> official MCP SDK
                                                    |
                                              tool callbacks
                                                    |
                                            Dishka ExecService
                                              |           |
                                     PostgreSQL        Kafka
                                              |           |
                                         in-flight     manager (fake in tests)
```

The tools are `exec_shell(command)` and `exec_python(code)`, in that order.
Each accepts one nonempty string and no other arguments. The string is passed
verbatim in the shared ads-commons handshake DTO; this service never runs it.
No Kubernetes, IPC, engine client integration, lab identity or Helm changes are
part of this slice.

## HTTP and security

- `POST /mcp`: stateless JSON-response Streamable HTTP, MCP `2026-07-28` only.
  The boundary rejects other version headers; the SDK validates the body and
  routing metadata. Authenticated `GET` and `DELETE` return SDK-owned 405.
- JWT verification requires audience `ads-sandbox-mcp`, then caller
  `azp=ads-engine`. Invalid credentials return 401; wrong caller returns 403.
  Only then are `x-ads-session-id` and `x-ads-message-id` parsed as UUIDs (400).
  The verified identity and ADS IDs are bound in `SecurityContextHolder`.
- Send `MCP-Protocol-Version`, `Mcp-Method`, and for calls `Mcp-Name`. The SDK
  checks them against JSON-RPC method/name and modern `_meta` fields. Tests
  assert 400 / `-32020` mismatches without an ADS protocol dispatcher.
- No session is minted. Notifications return 202. The SDK returns `-32601`
  for modern MCP `ping`, `initialize`, resources and prompts. No Tasks, MRTR
  or SSE support is enabled.
- `/health/live` and `/health/ready` are unauthenticated. Ready checks the local
  reply consumer loop, not manager availability.
- SDK 2.2.0 only watches disconnects on its SSE path. A thin ASGI event-forwarding
  wrapper cancels the JSON-response call on `http.disconnect`; it does not parse
  the body or implement MCP. Tests exercise the real SDK with ASGI disconnects.

MCP `ping` was removed in this protocol version. It is unrelated to ADS↔ads-engine
Kafka liveness pings or the manager↔IPC handshake; those contracts are unchanged.

## Execution and durable state

The service mints an execution UUID and a fresh STE token for audience
`ads-sandbox-manager`, inserts an in-flight row in its dedicated Postgres database,
then publishes `request` to `ads.sandbox.exec.request`. All outbound messages use
the raw STE JWT in Kafka header `authorization`. STE is performed separately for
`request`, `ack-reply`, `ack-reset` and `abort`, without caching.
All four carry the required `execution_id`, `session_id`, `message_id` tuple and
use `session_id` as the Kafka key. Controls are populated from the durable row,
not from the reply token or an HTTP holder. Incoming `acknowledge` also carries
that tuple and must match the durable row before changing the deadline, replying,
or clearing a timeout tombstone. Missing or malformed IDs fail wire decoding.

The reply controller verifies audience `ads-sandbox-mcp` and caller
`ads-sandbox-manager` on `ads.sandbox.exec.reply`. It never binds the reply token
to the HTTP security holder. Each process has a unique consumer group and seeks
to the end on assignment; startup does not truncate the table.

| Event | Durable action | Manager control |
| --- | --- | --- |
| Live first acknowledgement | Reset deadline to the same timeout; record acknowledgement | `ack-reply` |
| Duplicate live acknowledgement | Do not extend the deadline | None |
| Timeout/cancel before acknowledgement | Retain tombstone | No premature abort |
| Timeout/cancel after acknowledgement | Retain tombstone | `abort` |
| Acknowledgement against a tombstone | Delete only after successful reset publication | `ack-reset` |
| Acknowledgement with no row | Ignore | None |
| Result with local waiter and live row | Delete row, complete waiter | None |
| Late/missing-ID result | Drop and warn, without output/token logging | None |

PostgreSQL row locks serialize acknowledgements against timeout/cancel across
replicas. A local waiter lock serializes result commit against watchdog completion.
The row contains execution/session/message UUIDs, creation/deadline timestamps and
two handshake flags. It contains no credentials, payload, stdout/stderr or replica ID.
STE/insert failures return an immediate tool error; failures after insert follow
the watchdog. Client disconnection takes the same tombstone/control path.

The cluster scheduler holds a PostgreSQL session advisory lock on a dedicated
connection. One leader runs collection every timeout, deleting rows older than
twice that timeout. Connection loss releases leadership. An abandoned process has
no recoverable HTTP waiter; tokens are deliberately never recovered from storage.

Kafka publication and PostgreSQL commits are not a distributed transaction.
Control publication is bounded and best-effort: a broker acknowledgement followed
by a DB failure can leave uncertain delivery. This is not an exactly-once execution
guarantee. Manager duplicate handling and its own handshake timeout remain required.
If storage stays unavailable for a timeout, the HTTP waiter fails closed rather than
waiting forever. No code can commit a tombstone while Postgres is unavailable;
the retained deadline rejects a late acknowledgement after recovery, or GC removes
the abandoned row. Post-ack abort remains best-effort during infrastructure outages.

## Configuration

All names below have prefix `ADS_SANDBOX_MCP_`.

| Suffix | Required/default |
| --- | --- |
| `DATABASE_URL` | Required dedicated `postgresql+psycopg://...` database |
| `KEYCLOAK_WELL_KNOWN_URL` | Required discovery URL |
| `KEYCLOAK_ISSUER` | Required issuer |
| `KEYCLOAK_CLIENT_SECRET` | Required confidential-client secret |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | Required; validated before database/network startup |
| `TLS_CA_BUNDLE` | Optional private CA for outbound identity/JWKS/STE HTTPS |
| `KAFKA_BOOTSTRAP_SERVERS` | Required broker list |
| `BIND_HOST`, `PORT` | `0.0.0.0`, `8080` |
| `TIMEOUT_SECONDS` | `120`, finite and positive; reset once on first acknowledgement |
| `STDOUT_BYTES`, `STDERR_BYTES` | `65536` each |
| `INPUT_BYTES` | `262144` |
| `ALLOWED_HOSTS` | `ads-sandbox-mcp,ads-sandbox-mcp:*`; configure actual service DNS names |
| `ALLOWED_ORIGINS` | Empty; comma-separated browser origins if explicitly needed |

No HTTP/TLS toggle exists. Client and audience are fixed to `ads-sandbox-mcp`;
manager audience/caller are fixed to `ads-sandbox-manager`. Kafka SASL/ACL and
lab identity provisioning are deferred to their planned slices.

Alembic migrations run and mapped schema validation completes before uvicorn.
The Containerfile preserves the workspace migration files and runs as UID 1000.
GitHub Actions lints/builds/smokes the new image without publishing it.

## Result contract and proof

`structuredContent` always contains `exit_code`, `stdout`, `stderr`, `truncated`,
and `duration_ms`. Nonzero process exits have `isError=false`; setup failures,
manager errors, not-ready and timeouts have `isError=true`. UTF-8 byte caps apply
to both output fields and the mirrored text result; no uncapped tail is retained
in a second result field. Unknown tools or invalid/oversized input return `-32602`.

Run the repository's standard gates:

```sh
uv run --group dev nox -s lint deps typecheck test package
```

The package uses the repository's existing index setup; this slice does not
change the project package policy. Tests fake Kafka, manager and token exchange,
but use real PostgreSQL for migrations, row locks and advisory leadership.
CI uses Testcontainers `postgres:16-alpine`. For an existing disposable local
database, set `ADS_MCP_TEST_DATABASE_URL=postgresql+psycopg:///ads_sandbox_mcp_test`.
The fixture clears `sandbox_execution`; never point it at a live database.

`tests/sandbox_fixtures.py` is shared by the MCP tests and the manager's deterministic
cross-service handshake tests. It provides settings, a disposable PostgreSQL
database/schema, an engine, and the harness; `sandbox_support.py` contains the
controlled doubles, named overrides, and shared row/message helpers. The manager
keeps its own database and Alembic head through `ADS_MANAGER_TEST_DATABASE_URL`.
The existing ack/reset/abort, timeout, identity, and HTTP-disconnect assertions
remain in place. Cross-service tests supplement them with real services, SQL
repositories, signed JWT verification, and STE adapters, while Kafka, the identity
endpoint, Kubernetes, and guest processes remain simulated. This is not a live
Kafka/Keycloak/Kata acceptance proof.
