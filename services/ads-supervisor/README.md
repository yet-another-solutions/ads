# ads-supervisor

The policy enforcement point in front of the agent. One process serves one run: it opens
the run, answers the agent's permission requests by asking the policy service, and
records the answers the policy service never saw.

## Why it is a separate process

The agent executes tools in its own process. An agent with `process.exec` inside its
boundary reaches any file, process and port on its side of it — so whatever answers
"may I" must live on the other side, where the agent cannot kill it, patch its config
or forge its replies.

```
   agent        ← executes tools, not trusted
  ───────────   ← boundary: filesystem, network, processes, (in vm: kernel)
   supervisor   ← decides what is allowed; the agent cannot reach it
```

The test for any new component is the same question: if the agent runs an arbitrary
command, does it reach this? If yes, the component is on the wrong side.

The same code is meant to run in both modes — on a developer machine next to a
devcontainer, and in the cluster next to a run pod. The difference is the transport to
the agent and who creates the pod, not the decisions.

## What it does not do

It does not decide, and it does not translate. The tool call goes on in the agent's own
words — `{source, tool, arguments}` — and the policy service says both what that amounts
to and whether it is allowed. The bindings that turn `bash` into `process.exec` are
policy, pinned to the run along with the rules; a copy kept here would decide under a
version nobody recorded.

`rm -rf /workspace` and `uv sync` come out as the same `process.exec`, and the difference
between them is not this service's to find — the boundary is isolation, not command
parsing.

The one thing it does look at is the outbound payload: once the matrix has permitted a
call, a credential among its arguments turns the permission into a refusal. That check
runs here rather than in the policy service because the payload is already in hand.

It also does not describe the agent's placement from what the agent says. The run is
opened with the placement this process was configured with, and the level follows from
that.

## API

`/supervisor` requires `Authorization: Bearer $ADS_SUPERVISOR_API_TOKEN`; health is
public.

| | |
|---|---|
| `POST /supervisor/permissions` | `{source, tool, arguments}` → the decision |
| `GET /supervisor/run` | the run this process serves |
| `GET /health/live` | the process is up |
| `GET /health/ready` | a run is open. 503 otherwise |

## Configuration

Required:

- `ADS_SUPERVISOR_API_TOKEN` — at least 16 characters
- `ADS_POLICY_URL`, `ADS_POLICY_API_TOKEN`
- `ADS_AMQP_URL`
- `ADS_SUBJECT`, `ADS_PROJECT`, `ADS_REPO` — the run is opened on behalf of someone,
  on something
- `ADS_TLS_CERT_PATH`, `ADS_TLS_KEY_PATH`

Optional: `ADS_ENV` (`dev`), `ADS_RUN_WORKDIR` (`/workspace`), `ADS_TLS_CA_BUNDLE`,
`ADS_BIND_HOST` (`0.0.0.0`), `ADS_PORT` (`8080`), `ADS_ATTRIBUTES` (`key=value,…`).

Placement:

- `ADS_PLACEMENT` — `cluster` (default) or `workstation`
- `ADS_NODE_LABELS`, `ADS_RUNTIME_CLASS_NAME` — for a cluster placement, what the pod
  actually landed on

Describe only the placement the process really has. Claiming a sandbox it does not have
hands an ordinary container the rules written for a Kata guest, which is the whole
reason the level is derived rather than declared.

## Journalling

The policy service records every decision it makes, so this side does not record them
again — a second copy would read as a second attempt and charge the budget twice. What
it does publish is the decisions it made *instead of* the policy service, when that was
out of reach. Those would otherwise leave no trace, and a break in the network would
quietly erase a stretch of history.

The buffer has a ceiling. A denial that cannot be journalled is still a denial, so
nothing is granted in that state.

## Not built yet

opencode. The supervisor has the shape of the enforcement loop but nothing drives it:
in the finished system the entry point is an SSE subscription to `GET /event` on the
agent's API and a reply to `POST /session/{id}/permissions/{id}`, spoken over the
public server API only — no patches, no forks, the version pinned exactly.

Nothing here creates a pod either; in cluster mode that belongs to the run service.
