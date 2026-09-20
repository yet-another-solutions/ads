# ADS context compaction v1

`ads-context-compactor` is an internal HTTPS REST service, not a Kafka consumer.
`POST /compact` accepts `CompactRequest` from `ads-commons` and returns one
`Tombstone` (HTTP 200). JWT verification requires its own audience and
`azp=ads-engine`; no user role substitutes for that caller check. The service
uses fresh Standard Token Exchange V2 to call the existing meter, which allows
both the engine and compactor callers.

## Ownership and algorithm

The compactor owns its LangGraph split/replace loop. It selects the next safe
user boundary at or beyond 50% of the current ADS-list token estimate, backing
off through 40%, 30%, 20%, 10% only on frame/provider overflow. Repeated resolved
boundaries are skipped. Tool pairs and explicit `TaskTransition` lifecycles
cannot cross a split; unknown lifecycle evidence fails closed.

The model emits only
`<ads-compaction-result>{"summary":"..."}</ads-compaction-result>`.
The runtime parses the strict envelope, performs at most one tool-free format
repair, verifies the summary cap, and builds the UUID, archive, inner memory and
untouched remainder itself. A replacement must save at least 10% of its selected
prefix, including visible memory metadata. Each accepted round resets to 50%.
The target is a fixed percentage of model `max_context_tokens`, not a percentage
of each successive working list. There is no whole-context final pass. An
unreachable target fails the invocation.

The only active projection is the new memory plus its top-level remainder once.
Recall unwraps inner memory plus archived originals, never a prior remainder.
`ads-context-runtime` is a workspace library used locally by both the compactor
and engine, not another service. Each recall frame owns a local LangGraph and
only `remaining_context` and visible-memory `memory_recall` tools. It has no MCP
dispatcher or executor. Model credentials remain in adapter closures, not graph
state, archives, or persistent traces; tracing is disabled on these graphs.

## Capacity and failure rules

The existing meter counts ADS message lists only. System prompts, tool schemas
and provider wrappers remain outside the estimate in v1. The runtime reserves
output space, checks parent and child admission separately, retains frame
exchanges, and disables both recall tools below 10% remaining capacity (exactly
10% is allowed). Results are metered with their call/result metadata before
parent insertion. Numeric metadata can affect its own count; reported remaining
capacity uses a conservative non-overstated fixed point.

An oversized answer receives one shorter-answer retry outside parent context.
If it still cannot fit, the runtime inserts a small prohibition result and forces
bounded tool-free finalization. Oversized source, meter failures and provider
overflow fail explicitly; no source compaction, truncation, tokenizer fallback,
global invocation cap or automatic external-action replay is added.

## Engine, stream and persistence

Engine LangGraph checks context at admission and after a complete model/tool
step, including a terminal assistant response with no next model invocation.
Compaction emits three independent ordered parts: `compacting_context`,
`compacted_context`, then `tombstone`. Every engine part includes pressure and the
originating request message ID. Existing part numbering and finish last-order
completeness govern promotion; pings continue independently through REST and
recursive recall waits.

ADS appends a hidden tombstone at its actual entry-list position and records a
run-local candidate pointer. Only a complete successful finish commits the latest
candidate to the session. Next-run history starts with that memory and its
remainder, followed by later message/tool entries. Failed runs remove their user
turn, parts, buffers and candidates, preserving the previous committed pointer.
Mismatched request IDs cannot finish or append to a later run. Full session
rerender rewinds the UI; the green pressure meter appears above the composer only
while active and uses the latest contiguous part.

## Configuration and installation

Fresh model configurations require a positive integer `max_context_tokens`.
This change updates the fresh schema only: there is no new migration revision,
backfill, legacy-record repair, deployment action, or database wipe.

Engine settings:

| Environment variable | Default |
| --- | --- |
| `ADS_ENGINE_CONTEXT_METER_URL` | `https://ads-context-meter:8443/meter` |
| `ADS_ENGINE_CONTEXT_COMPACTOR_URL` | `https://ads-context-compactor:8443/compact` |
| `ADS_ENGINE_CONTEXT_TRIGGER` | `80` |
| `ADS_ENGINE_CONTEXT_TARGET` | `50` |
| `ADS_ENGINE_CONTEXT_OUTPUT_RESERVE` | `1024` |

Compactor requires `ADS_CONTEXT_COMPACTOR_KEYCLOAK_WELL_KNOWN_URL`,
`ADS_CONTEXT_COMPACTOR_KEYCLOAK_ISSUER`,
`ADS_CONTEXT_COMPACTOR_KEYCLOAK_CLIENT_SECRET`,
`ADS_CONTEXT_COMPACTOR_TLS_CERT_PATH`, and `ADS_CONTEXT_COMPACTOR_TLS_KEY_PATH`.
Optional `ADS_CONTEXT_COMPACTOR_TLS_CA_BUNDLE` applies to outgoing HTTPS.
`ADS_CONTEXT_COMPACTOR_METER_URL` defaults to
`https://ads-context-meter:8443/meter`; `RESERVED_OUTPUT_TOKENS` and
`SUMMARY_CAP_TOKENS` with the same prefix default to 1024 and 2048.
The model adapter has a 120-second invocation timeout and the REST client a
300-second timeout, with no automatic model retry inside recall/compaction.

Helm supplies the actual service URLs and ports, a dedicated certificate and
internal ClusterIP, and references an existing Keycloak client-secret Secret.
There is no public route, service database or Kafka configuration. Provision the
standalone realm sample's new `ads-context-compactor` client and engine optional
`ads-engine-context-compactor` scope before a future installation. The existing
engine MCP refresh scope is not broadened. Current transport body/message limits
are unchanged; large serialized archives may fail despite a small visible summary.

Deterministic tests cover split/backoff/reset, parse repair, recall budgets and
recursion, REST authentication, tool-continuation and terminal boundaries,
independent pings, cancellation, candidate rollback, reconstruction and UI pressure.
They use scripted models, not a live LLM. CI builds the new image without publishing.
