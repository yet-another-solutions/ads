# ads-guardrail

The policy enforcement point in front of the agents. One shared service: agents reach
their MCP servers through it, and it asks the policy service about every tool call,
reads what goes out and what comes back, and records what the policy service never saw.

## Where it stands

```
   agent            ← executes tools, not trusted
  ───────────────   ← sandbox boundary: filesystem, network, processes, (in vm: kernel)
   ads-guardrail    ← decides what is allowed; the agent cannot reach it
        │
   MCP servers
```

It is one service outside every sandbox, not a sidecar in each. In a Kata pod every
container shares the VM, so a sidecar would sit inside the boundary it guards.

The test for any new component is the same question: if the agent runs an arbitrary
command, does it reach this? If yes, the component is on the wrong side.

## MCP

An agent's MCP client for server `name` is pointed at `/mcp/<name>` instead of the
server's own address. Nothing else changes on the agent's side. The guardrail speaks
MCP's Streamable HTTP transport through to the real server:

| | |
|---|---|
| `POST /mcp/<name>` | a `tools/call` is decided and its result read; anything else goes through as it is |
| `GET /mcp/<name>` | the stream the server writes to unasked; passed on |
| `DELETE /mcp/<name>` | the end of a session; passed on |

Headers go through both ways, the session id among them. An answer that is an event
stream stays a stream, read event by event. A batch carrying a `tools/call` is refused
whole. Strings inside messages are read, not the JSON text around them, so an escaped
secret is found and cutting one out leaves valid JSON.

The server's name is what bindings call it: `mcp:<name>`. Two servers may both offer
`search`, and they need not mean the same thing by it.

Each server is configured with its `site` — where it executes the tools it offers. The
isolation level of a call follows from the site of the server it goes to, not from the
run: one agent may use a server in a Kata VM and another on an ordinary node, and the
same tool is allowed at the first and refused at the second.

```
ADS_MCP_SERVERS='[{"name": "sandbox", "url": "http://ads-sandbox-mcp:8080/mcp",
                   "site": {"placement": "cluster", "runtime_class_name": "kata-clh",
                            "node_labels": {"ads.io/sandbox-node": "true",
                                            "ads.io/application-node": "true"}}}]'
```

A site the policy service cannot place is refused as `site.unknown`; a call with no site
at all, into a run that has no level of its own, is refused as `site.missing`.

## What it does not do

It does not decide, and it does not translate. The tool call goes on in the agent's own
words — `{source, tool, arguments}` — and the policy service says both what that amounts
to and whether it is allowed.

It does not guess who a task is for or what it works on: whoever creates the sandbox
says that when opening the run. Where tools execute is not the run's business either —
that is the server table's.

## Which run a call belongs to

A proxied call carries nothing but its `Authorization` header, so the run is found
from that — from who it names, not from the token itself. A person's token is replaced
while a long task runs; the person is not.

| caller | bearer | the run is held by | who opens and finishes the run |
|---|---|---|---|
| our sandbox service | the person's JWT | `user:<sub>` of the verified token | the service, per task |
| hermes | its `api_server_key` | `key:<sha256 of the key>` | this service, from `ADS_APPLICATIONS` |

A person's token is believed only once it verifies against Keycloak: signature, issuer,
expiry, and an audience of `ADS_MCP_AUDIENCE`. Without the audience check any token of
theirs — issued to some other application entirely — would act in their runs, so with
no audience configured no person is recognised at all. An expired token is refused;
the service refreshes it and carries on in the same run.

```
POST /guardrail/runs
{"bearer": "<the person's token>",
 "workspace": {"project": "ads", "repo": "…", "env": "dev", "workdir": "/workspace"}}
```

The person comes from the token, never from the caller's say-so. Neither the token
nor the key is kept anywhere; the holder is, in the policy service, where every
replica can see it.

A running run of the holder is the run. When they hold several — one person, two
sandboxes — the call names one in `x-ads-run`, and that run must be theirs: a run id
alone is not a credential. With nothing running but a run revoked or finished, that
run is used, so the policy service refuses the call and journals it. A call that
matches no run at all is refused with the ordinary refusal and never reaches the
server.

### What the sandbox service does

1. On creating a sandbox, opens a run: `POST /guardrail/runs` with the person's token
   and the workspace. The answer carries the run id.
2. Points the agent's MCP clients at `/mcp/<name>` here.
3. Sends, on every MCP call, `Authorization: Bearer <the person's token>` and
   `x-ads-run: <run id>`. Always, not only once a second task exists: otherwise a
   person's second task, started in parallel, would break the first.
4. Refreshes the token before it expires; the run does not change. The run itself
   needs no refreshing: every call moves its end, and it expires only after the
   policy service's `ADS_RUN_TTL_SECONDS` of silence.
5. When the task is over, finishes the run: `POST /guardrail/runs/{id}/finish`.
   Otherwise it lingers until its lifetime ends.

### Applications

hermes knows nothing about the guardrail, so nobody in its path would open a run for
it. It is configured here instead — its key's fingerprint and its workspace — and its
run is opened on its first call and again whenever the last one has finished or
expired. A revoked run is kept, not replaced: otherwise revoking an application would
mean nothing. To stop an application for good, take it out of the configuration.

```
ADS_APPLICATIONS='[{"name": "hermes",
                    "key_sha256": "<printf %s "$API_SERVER_KEY" | sha256sum>",
                    "workspace": {"project": "ads", "repo": "…", "env": "test",
                                  "workdir": "/workspace"}}]'
```

## API

`/guardrail` requires `Authorization: Bearer $ADS_GUARDRAIL_API_TOKEN`; `/mcp` and health
are public.

| | |
|---|---|
| `POST /guardrail/runs` | a person's token and the workspace → a run. For the launcher only |
| `POST /guardrail/runs/{id}/finish` | the task is over → the finished run |
| `POST /guardrail/permissions` | `{run_id, source, tool, arguments}` → the decision; a source `mcp:<name>` is decided at that server's site |
| `GET /health/live`, `/health/ready` | the process is up |

## Configuration

Required: `ADS_GUARDRAIL_API_TOKEN` (at least 16 characters), `ADS_POLICY_URL`,
`ADS_POLICY_API_TOKEN`, `ADS_AMQP_URL`, `ADS_TLS_CERT_PATH`, `ADS_TLS_KEY_PATH`.

Optional: `ADS_MCP_SERVERS` (JSON, above), `ADS_APPLICATIONS` (JSON, above),
`ADS_MCP_TIMEOUT_SECONDS` (`60`, the longest silence from a server), `ADS_RUN_HEADER`
(`x-ads-run`), `ADS_ATTRIBUTES` (`key=value,…`),
`ADS_TLS_CA_BUNDLE`, `ADS_BIND_HOST` (`0.0.0.0`), `ADS_PORT` (`8080`), `ADS_BUILD`.

People's tokens: `ADS_MCP_AUDIENCE`, and with it `ADS_KEYCLOAK_WELL_KNOWN_URL` and
`ADS_KEYCLOAK_ISSUER`. The signing keys are fetched at startup; a Keycloak that cannot
be reached stops the process rather than failing every call later.

## Journalling

The policy service records every decision it makes, so this side does not record them
again — a second copy would read as a second attempt and charge the budget twice. What
it does publish is what it decided itself: payload findings, and decisions it had to
make when the policy service was out of reach. Every row names the build that wrote it.

The buffer has a ceiling. A denial that cannot be journalled is still a denial, and a
secret whose redaction cannot be journalled is still redacted.
