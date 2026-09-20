# ads-context-meter

Stateless, internal REST service estimating the token size of submitted ADS
context primitives through LiteLLM. One image and one Kubernetes Deployment;
each pod has a TLS REST process and one local counting subprocess, not a second
service. No database, Kafka consumer, provider API invocation, or model credentials.

## Contract

`POST /meter`, `Content-Type: application/json`:

```json
{
  "model_name": "glm-5.3",
  "messages": [
    {"type": "system", "text": "You are an assistant."},
    {"type": "user", "text": "Inspect the project."},
    {"type": "reasoning", "text": "First inspect its files."},
    {"type": "tool_call", "id": "call-1", "name": "exec_shell", "arguments": {"command": "ls"}},
    {"type": "tool_result", "tool_call_id": "call-1", "name": "exec_shell", "status": "success", "content": {"stdout": "README.md"}},
    {"type": "assistant", "text": "The project has a README."}
  ]
}
```

HTTP 200: `{"estimated_tokens": 123}` (illustrative number).
`model_name` is required and validated against the `ads-commons` model catalog:
`glm-5.2` or `glm-5.3`. No normalization, arbitrary tokenizer path/URL, or
unknown-model fallback. DTOs and `ContextMeterApi` live in
`ads_commons.context_meter`. Existing user, assistant, tool-call, tool-result,
and reasoning definitions are reused; reasoning gets a discriminator for the
heterogeneous list, and system text is a context-specific shared primitive.

The caller supplies exactly the context to count, including instructions and
current user input if desired. The meter does not fetch session history or add
hidden prompts. List items represent complete primitives, not streaming deltas.
Unknown primitive types and malformed requests return 400.

## Estimate semantics

This is a local estimate, not the provider's authoritative prompt usage or a
context-limit enforcement decision. LiteLLM's generic message overhead and reply
priming are included; an empty list currently estimates 3 priming tokens.
Reasoning is retained as `<think>…</think>` assistant text. Tool envelopes are
compact JSON text, including call IDs, names, arguments, status, and result
content, so LiteLLM does not silently omit tool names. Storage/trace `metadata`
is excluded. Each primitive contributes its own message framing, so split
deltas must be assembled by the caller first.

GLM provider chat templates, grouping of assistant/tool messages, provider
reasoning retention, and tool-definition schemas may differ. Tool-definition
schemas and multimodal assets are not part of v1. URLs inside content remain
text and are never fetched. The engine and compactor now call this endpoint for
active-list accounting. Tombstones count only their visible memory ID, summary
and recall instruction, never embedded archives or remainders. The caller submits
the top-level remainder separately exactly once.

## Security and offline assets

The REST process verifies the normal RS256 JWT (`iss`, `aud`, expiry, signature,
UUID subject) and binds the standard security holder. Both middleware and the
service enforce callers `ads-engine` and `ads-context-compactor`.
No role is required. Missing/invalid authorization is 401; a different/missing
caller is 403. Only `/health/live` and `/health/ready` are public.

Callers use fresh Standard Token Exchange V2 with audience `ads-context-meter`.
Engine requests optional scope `ads-engine-context-meter`; compactor has a direct
meter audience mapper and uses its own confidential client. The standalone Keycloak sample
adds this scope only to the engine's optional scopes; it must never be requested
for the MCP access/refresh pair or made a default scope. The meter itself is a
resource server and needs no client secret at runtime.

`bake.py` is an image-build step in GitHub Actions. It downloads only official
`tokenizer.json` files at full revision SHAs and checks SHA-256 digests declared
in `assets.py`; there are no model weights or remote Python modules.
Runtime verifies both assets before listening and requires an explicit local
tokenizer on every LiteLLM count. Missing/corrupt assets fail startup; no download
or tiktoken fallback replaces a GLM tokenizer.

The counting worker installs a fail-closed Linux libseccomp filter before
LiteLLM import: new sockets, outbound socket syscalls and exec are denied at
the kernel boundary, including native libraries. Parent/worker communication
uses existing local process-pool pipes. Worker subprocesses/threads inherit the
restriction; the REST process still reaches Keycloak discovery/JWKS normally.
LiteLLM uses its bundled local cost map, HF offline mode, disabled telemetry,
and its wheel-bundled default encoding assets for internal lazy imports.
Only request DTOs cross the pool, never JWTs or the security holder.

CI runs the built image with `--network none --read-only --tmpfs /tmp` and empty
user/HF caches, exercising both real GLM tokenizers and all primitive kinds.
Python tests use a tiny local tokenizer fixture and kernel network-denial
tests. The runtime image requires Linux and `libseccomp2`; failure to install
the filter is fatal, not a permissive fallback.

## Deployment

Helm's `contextMeter` values configure replicas, image, HTTPS Service port,
Keycloak issuer/discovery/audience and optional BYO TLS secret. There is no
HTTPRoute/Ingress. The default internal address is
`https://ads-context-meter:8080/meter` for release `ads`.
cert-manager issuance, optional CA bundle, ServiceAccount and application-node
placement follow existing ADS conventions.

Environment prefix: `ADS_CONTEXT_METER_`. Required: `TLS_CERT_PATH`,
`TLS_KEY_PATH`, `KEYCLOAK_WELL_KNOWN_URL`, `KEYCLOAK_ISSUER`.
Defaults: `KEYCLOAK_AUDIENCE=ads-context-meter`, `TOKENIZER_DIRECTORY=/opt/tokenizers`,
`BIND_HOST=0.0.0.0`, `PORT=8080`. Optional: `TLS_CA_BUNDLE`.
Maximum JSON request size is 16 MiB; each pod counts one request at a time.

Tokenizer provenance:
- [Official GLM-5.2 repository](https://huggingface.co/zai-org/GLM-5.2)
- [Official GLM-5.3 repository](https://huggingface.co/zai-org/GLM-5.3)
- [LiteLLM custom local tokenizer and cost-map documentation](https://docs.litellm.ai/docs/completion/token_usage)
