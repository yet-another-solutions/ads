# ads-policy

The policy decision point. It is the only thing in ADS that decides whether an agent
may do something, and every enforcement point — the web app, the guardrail, later the
egress control plane and the tool broker — asks it rather than deciding for itself.

A decision is a function of four things: the capability, the resource, the isolation
level of the run, and the attributes of the subject. The service never inspects the
command, the SQL or the diff; it matches a normalised capability against a matrix.

## What it decides on

Capabilities are normalised and the set is closed: `fs.read`, `fs.write`,
`process.exec`, `net.egress`, `db.query`, `db.migrate`, `secret.read`, `vcs.push`.
There is deliberately no `db.write` (the object of control is a migration file in git)
and no `deploy` (the deployment boundary belongs to CI).

The resource is classified by the service, never by the caller: a path is inside the
workdir or outside it, a host is on the egress allowlist or is the internet, a branch is
protected or is not. Path traversal, URL userinfo and `refs/heads/` prefixes are
resolved before the rule is matched. Which classifier applies to which capability is
policy; the five kinds behind them — path, suffix, host, branch, literal — are code.

Recognising an agent's tool call is also the service's job, not the caller's. A binding
says what `bash` from `opencode` amounts to and which argument it acts on, so the matrix
stays written over capabilities while foreign tool names live in one place. Bindings are
pinned to the run with everything else: one added mid-run does not change what that run
may do, and a tool nothing binds is refused.

A tool server can be taken out of checking altogether: `sources: {"mcp:jira": {checks:
"off"}}` in the policy document. Its calls then need no binding, meet no rule and are
not scanned. Each one is still journalled, allowed under `source.unchecked` with weight 0
and naming the server and tool it went to. A run that is unknown, someone else's or over,
and a blocked chat, still refuse it.

Isolation levels are `local`, `container` and `vm`. `container` and `vm` are derived
from where the run was actually scheduled; `local` is asserted by whoever opens a run
on a developer machine, because node labels are a cluster notion. A cluster placement
that resolves to nothing is a refusal, not a weaker level.

A decision may carry its own `site` — where the tool is actually executed, such as the
MCP server a call goes to. The level is then derived from that site and outranks the
run's. A run may be opened with no placement at all (`"placement": null`); it has no
level of its own, and every call into it must bring a site or is refused as
`site.missing`.

## API

All `/policy` routes require `Authorization: Bearer $ADS_POLICY_API_TOKEN`. Health is
public. Everything is HTTPS; there is no plain-HTTP mode.

| | |
|---|---|
| `POST /policy/runs` | open a run. The body describes the placement, if any; the level is derived from it |
| `POST /policy/runs/{id}/revoke` | revoke a run. The next decision sees it |
| `POST /policy/conversations/{id}/revoke` | `{budget, by}` → block a chat for good: every decision in any run carrying that `conversation` is refused as `conversation.revoked`, in either mode. Sent by the audit service |
| `POST /policy/decide` | a decision for one capability and resource within a run |
| `POST /policy/calls` | a decision for one tool call, named as the agent names it |
| `POST /policy/prompts` | `{run_id, subject}` → what the checks on the prompt side are for this run. The content itself stays with the guardrail |
| `GET /policy/version` | schema version, policy version, the hash the service computed, mode |
| `GET /policy/sources` | every source the current policy names, with its checks: `enforce` or `off` |
| `GET /health/live` | the process is up |
| `GET /health/ready` | the run store answers. 503 otherwise |

A decision carries two texts. `reason` is for the journal and may describe the
boundary. `message` is what the agent is allowed to see: either a permitted
alternative or nothing at all, never a map of what else is forbidden.

## Configuration

Required:

- `ADS_POLICY_API_TOKEN` — at least 16 characters
- `ADS_REDIS_URL` — runs live here, with the key's lifetime as their own
- `ADS_AMQP_URL` — decisions are published to the `ads.audit` exchange
- `ADS_TLS_CERT_PATH`, `ADS_TLS_KEY_PATH`

Optional, with defaults:

- `ADS_TLS_CA_BUNDLE`, `ADS_BIND_HOST` (`0.0.0.0`), `ADS_PORT` (`8080`)
- `ADS_POLICY_DIR` (`/policy`) — a mounted `policy.json` replaces the built-in matrix
- `ADS_POLICY_MODE` (`enforce`) — `review` records decisions without applying them
- `ADS_POLICY_DENY_ON_ERROR` (`true`)
- `ADS_SANDBOX_AVAILABLE` (`true`) — the chart computes this; without Kata no run is
  ever assigned `vm`
- `ADS_RUN_TTL_SECONDS` (`3600`) — how long a run lives without a decision. Every
  decision in a running run starts the count again, so a task in use never runs out
  and a forgotten one does; a revoked or finished run is not extended
- `ADS_RUN_WORKDIR` (`/workspace`)
- `ADS_EGRESS_ALLOWLIST`, `ADS_PROTECTED_BRANCHES` — comma separated

Everything else — rule weights, the repeat multiplier, secret patterns, node labels —
lives in `GovernanceSettings` in `config.py`. Modules read those settings; none of them
redefine a constant of their own.

## How it fails

Closed, in every direction. An unreachable Redis, a policy that cannot be evaluated, a
run that is revoked, finished or past its lifetime, a decision that cannot be journalled
— each is a denial, and each is recorded as one. Invalid TLS material or a missing
required variable stops the process at startup with exit code 3 rather than leaving a
listener that fails its probes.

## Client

`ads_policy.client` ships the client for this API, so enforcement points depend on this
package rather than on each other. `HttpPolicyClient` turns any failure to reach the
service — connection error, 5xx, an answer it cannot read — into a denial with rule
`policy.unreachable`.

## Not built yet

Runs are in Redis rather than PostgreSQL, and the run lifecycle still lives here
instead of in a separate session service. Escalation to a human is modelled in the
contract (`deny` carrying an `approval` block) but nothing fills it in.
