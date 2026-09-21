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
untouched remainder itself. A replacement must save at least the configured
minimum reduction (10% by default) of its selected
prefix, including visible memory metadata. Each accepted round resets to 50%.
The target is a fixed percentage of model `max_context_tokens`, not a percentage
of each successive working list. There is no whole-context final pass. An
unreachable target fails the compaction request. Engine handling depends on
whether the user turn has started, as described below.

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
exchanges, and disables both recall tools below the configured remaining-capacity
floor (10% by default; equality is allowed). Results are metered with their call/result metadata before
parent insertion. Numeric metadata can affect its own count; reported remaining
capacity uses a conservative non-overstated fixed point.

Provider-emitted batches in compactor/recursive frames are processed sequentially. All call envelopes and a
prohibition result for every outstanding ID are budgeted before any child starts.
Each accepted answer replaces its reserved result and is charged before dispatch
of the next call. Once starvation is reached, all remaining IDs receive error
results without execution, and subsequent finalization has no tools. If required
error closures cannot fit, the invocation fails rather than truncating evidence.
Only engine top-level calls/results are streamed into the session and UI.
Nested frame exchanges remain local. Mixed top-level recall/MCP batches fail closed.

Top-level engine recall does not use parent starvation admission. Its separately
configured evidence worker returns a bounded result; the complete provider batch
is preserved and context compaction runs at the next safe boundary before the
engine model continues. A worker can prohibit its own nested tools without
prohibiting the engine's top-level recall call. Worker source overflow remains a
hard failure; an answer violating its visible-size limit twice returns
`recall_answer_limit_exceeded`. Safe-split limitations remain unchanged.

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

Before the first model invocation for a new user turn, required compaction failure
is a hard error to ADS. After a model/tool step, compaction failure instead latches
complete-only mode for the rest of that turn: preserve the unchanged active
context, supply no tools (including local recall), and ask the model for its final
answer using existing evidence. Runtime dispatch rejects any further tool use,
even if a provider emits tool calls without schemas; such calls are not executed
or added as unresolved tool records. No further compaction is attempted in that
turn. If the assistant already finished without tools, retain that answer and
finish without an extra model call. The compaction failure itself produces no
Kafka error/abort, so normal successful finish preserves the turn and commits the
latest earlier successful compaction candidate, if any. A failed compaction never
produces a `compacted_context` or candidate tombstone.

This does not suppress cancellation, unrelated tool/meter failures, or failure of
the final model call itself. In particular, v1 token estimates cannot guarantee
that an uncompacted input will fit the provider's actual context window.

Every executor model turn receives refreshed `total_context_tokens` and
`remaining_context_tokens` in its system instructions, including after successful
compaction and during complete-only fallback. Remaining tokens are
`max(0, total - measured active context)`. The prompt labels this as an estimate
excluding instructions, schemas and provider overhead; it grants no permission
and does not replace runtime enforcement.

ADS appends a hidden tombstone at its actual entry-list position and records a
run-local candidate pointer. Only a complete successful finish commits the latest
candidate to the session. Next-run history starts with that memory and its
remainder, followed by later message/tool entries. Failed runs remove their user
turn, parts, buffers and candidates, preserving the previous committed pointer.
Mismatched request IDs cannot finish or append to a later run. Full session
rerender rewinds the UI; the green pressure meter appears above the composer only
while active and uses the latest contiguous part.

## Content-free operational diagnostics

Engine supplies optional `session_id`, `message_id`, per-attempt `compaction_id`
and `boundary` (`admission`, `continuation`, `finish`) on `CompactRequest`. These
are diagnostic metadata only, never authentication or source context.

Compactor lifecycle logs render structured JSON fields in the actual log message,
so the standard service formatter does not discard them. Events cover start,
measured split candidates (bounded to 20), selected/skipped splits, prefix overflow,
format repair, replacement reduction, success, cancellation and failure. They
include correlation IDs, boundary, model name, total/target/source token counts,
message counts, round and elapsed milliseconds. Failure reasons are allowlisted
codes such as `no_safe_fitting_prefix`; unknown exceptions report `internal_error`.
No messages, summaries, tool arguments/results, request objects, provider response
bodies, credentials or exception tracebacks are logged.

HTTP 422 responses include the same safe reason in the shared `CompactFailure`
DTO. Engine logs the reason and IDs when entering complete-only or rejecting
admission. Failure-code propagation does not trust arbitrary response text.

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
| `ADS_ENGINE_INNER_RECALL_RESERVED_OUTPUT_TOKENS` | `1024` |
| `ADS_ENGINE_INNER_RECALL_STARVATION_PERCENTAGE` | `10` |
| `ADS_ENGINE_INNER_RECALL_ANSWER_CAP_TOKENS` | `1024` |
| `ADS_ENGINE_INNER_RECALL_COMPLETION_CAP_TOKENS` | `1024` |
| `ADS_ENGINE_TOP_LEVEL_RECALL_RESERVED_OUTPUT_TOKENS` | `1024` |
| `ADS_ENGINE_TOP_LEVEL_RECALL_ANSWER_CAP_TOKENS` | `1024` |
| `ADS_ENGINE_TOP_LEVEL_RECALL_COMPLETION_CAP_TOKENS` | `1024` |
| `ADS_ENGINE_TOP_LEVEL_RECALL_STARVATION_PERCENTAGE` | `10` |

Compactor requires `ADS_CONTEXT_COMPACTOR_KEYCLOAK_WELL_KNOWN_URL`,
`ADS_CONTEXT_COMPACTOR_KEYCLOAK_ISSUER`,
`ADS_CONTEXT_COMPACTOR_KEYCLOAK_CLIENT_SECRET`,
`ADS_CONTEXT_COMPACTOR_TLS_CERT_PATH`, and `ADS_CONTEXT_COMPACTOR_TLS_KEY_PATH`.
Optional `ADS_CONTEXT_COMPACTOR_TLS_CA_BUNDLE` applies to outgoing HTTPS.
`ADS_CONTEXT_COMPACTOR_METER_URL` defaults to
`https://ads-context-meter:8443/meter`; `RESERVED_OUTPUT_TOKENS` and
`SUMMARY_CAP_TOKENS` with the same prefix default to 1024 and 2048.
Additional settings with that prefix are `COMPLETION_CAP_TOKENS` (2048),
`STARVATION_PERCENTAGE` (10), `RECALL_RESERVED_OUTPUT_TOKENS` (1024),
`RECALL_ANSWER_CAP_TOKENS` (1024), `RECALL_COMPLETION_CAP_TOKENS` (1024),
`RECALL_STARVATION_PERCENTAGE` (10), and `MINIMUM_REDUCTION_PERCENTAGE` (10).
Summary/repair frames use the compactor's own reserve and starvation floor;
their recall workers use the separate `RECALL_*` values at every recursive depth.
Engine top-level and engine inner recall have independent configurations and
never supply defaults to compactor recall.
Provider completion allowances include any provider-counted reasoning and are
distinct from metered final-answer limits. They are clipped to metered available
frame capacity including the output reserve. The one shorter-answer retry halves
both its visible answer cap and provider allowance.
See [Helm context budget settings](../../charts/ads/README.md#context-budget-settings)
for the complete values mapping and validation.
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
