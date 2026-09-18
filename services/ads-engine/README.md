# Engine sandbox executor

The application provider wires `ExecutorChatStreamer`, a bounded LangChain loop,
not a prompt-directed dispatcher. It discovers the server and lists exactly
`exec_shell(command)` and `exec_python(code)` using MCP SDK 2.2.0 in explicit
2026-07-28 mode. There is no legacy initialize, MCP ping, SSE session, resource,
task protocol, or fallback to tool-free chat if MCP setup fails.

## Execution boundary

Only a complete provider-native executor tool call, admitted under its run UUID,
and a current verified `user` authorization can reach `tools/call`. The entire
batch is checked before the first side effect. Calls are sequential, even if a
provider returns multiple calls despite `parallel_tool_calls=False`. The runtime
enforces the configured total tool budget; argument names, types, nonempty
strings, extra fields, and duplicate call IDs are checked.

The tool result goes back to the executor as a tool message. A nonzero process
exit is a successful tool-layer response; `isError` is a tool-layer failure.
Kafka partial output remains reasoning and assistant text only, never tool calls.
The separate `LangChainChatStreamer` is tool-free: thinker text, JSON proposals,
or native-looking calls do not obtain MCP sessions, credentials, or dispatch.

Provider calls can retry twice more only before any output or tool dispatch.
Transport, credential, or post-dispatch failures end the run with a sanitized
processing error; they never replay a possibly executed command. Cancellation
closes the active HTTP operation. Engine ping runs independently after ack-response
and is stopped on finish/error/abort, along with the in-flight DB claim.

## Run-local identity

After acknowledgement, the engine requests an access/refresh pair with one STE
using the original inbound user token, client `ads-engine`, target
`ads-sandbox-mcp`, and `requested_token_type=refresh_token`. The acknowledgement
STE remains access-only with optional scope `ads-engine-ack`.

Only the watcher renews, by refresh grant. It monitors access expiry and starts
refresh at twice the configured MCP timeout, not at an SSO-idle timer. There is
no self-STE, request-triggered renewal, lock, or refresh cache shared across runs.
Every POST, including discovery and listing, reads the current immutable pair
and sets bearer auth plus `x-ads-session-id` and `x-ads-message-id`.

Initial and replacement tokens must pass signature, issuer, expiry, UUID subject,
unchanged user identity, `azp=ads-engine`, exact singleton MCP audience, and scoped
realm `user` role checks. Extra realm/client roles and widened audiences are
rejected. Refresh must return a complete usable pair; tokens with at most twice
the MCP timeout remaining fail closed instead of creating a busy refresh loop.
Dispatch also rejects validity shorter than one MCP timeout. Refresh failure or
role revocation cancels execution and destroys the run-local pair.

Credentials stay in memory and are absent from model inputs, tool arguments,
checkpoints, DB state, Kafka output, and LangChain tracing. The engine explicitly
disables automatic LangSmith tracing around the credential-bearing execution.
Other service-to-service hops continue to mint fresh STE tokens.

## Proof and deployment boundary

Deterministic tests exercise the real SDK client and server with ADS auth
middleware and signed JWTs, fake model output, and a simulated guest callback.
They cover shell/Python sequencing, native-call authorization, no thinker
dispatch, current-token headers, refresh rotation/failure, cancellation, ping,
budget limits, schema rejection, and no side-effect replay.

The disposable Keycloak CI test imports the published realm sample, verifies
repeated refreshed audience/role claims and revocation, and keeps ACK routing
separate. A virtual-clock test covers execution past the original token expiry.
These are not live lab smoke results. Helm wiring, existing-realm reconciliation,
and full deployed Kafka/Keycloak/Kata proof remain deferred to their agreed stages.
