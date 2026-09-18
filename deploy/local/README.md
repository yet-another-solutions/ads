# Local cluster

The whole chain on a throwaway kind cluster: browser → ads → Kafka → engine → your
LLM → guardrail → MCP probe, with the policy service, the injection scanner and the
audit journal, all over TLS from a local CA and signed in through Keycloak.

## Run it

```sh
bash deploy/local/up.sh
```

Needs kind, kubectl, podman or docker, and internet access for the images and the
scanner's model (it is downloaded while the image is built). Podman is used when it
is installed (`ADS_CONTAINER_ENGINE=docker` to override), with kind's podman
provider. helm is optional: without it the script applies `rendered.yaml`, the same
chart rendered in advance — render it again after changing the chart or
`values-local.yaml` (the command is in its header). `ADS_SKIP_BUILD=1` skips
building and loading the images on a rerun. At the end the script prints what is
left to do by hand: `/etc/hosts`, two port-forwards, the LLM, and where to log in.

What it does, in order:

1. **kind cluster** `ads` (`ADS_KIND_CLUSTER` to change), and the nine images built
   as `localhost/<name>:local` and loaded into it — `values-local.yaml` sets
   `pullPolicy: Never`.
2. **Node label** `ads.io/application-node=true`. There is no Kata and no sandbox
   node, so the policy service is told there is no sandbox: nothing reaches level
   `vm`, and `process.exec` is refused. The MCP probe runs at the one site this
   cluster has, `probe-container`.
3. **cert-manager** and a local CA (`cert-manager-issuer.yaml`). The CA is copied into
   the namespace as `ads-ca`; every pod mounts it and trusts the others and Keycloak.
4. **Redis, RabbitMQ, PostgreSQL, Kafka** (`dependencies.yaml`). PostgreSQL creates
   `ads`, `ads_audit`, `ads_engine` and `ads_preferences`.
5. **Keycloak** (`keycloak.yaml`): realm `ads`, user `alice` / `alice`, and the clients
   the chain exchanges tokens between — `ads` → `ads-engine`, `ads-preferences`;
   `ads-engine` → `ads`, `ads-mcp`.
6. **CoreDNS** rewrites `keycloak.ads.local` to the Keycloak Service. Browsers and pods
   then use the same address, `https://keycloak.ads.local:8444`, and the issuer in a
   token is the same wherever it is checked.
7. **The chart** with `values-local.yaml` and `policy.example.yaml` as
   `policy.document` — the built-in rules plus the probe's bindings; through helm, or
   as `rendered.yaml` when there is no helm. Guardrail,
   scanner, probe and engine tools are on. The audit budget is 12, so a few refusals
   are enough to see a chat lose its tools.

## Use it

After `/etc/hosts` and the port-forwards the script prints, open
`https://ads.local:8443`, log in as `alice`, and add a model in the catalog. The model
runs on your machine (Ollama with `OLLAMA_HOST=0.0.0.0`, LM Studio, vLLM) and must be
able to call tools. On Linux pods reach it through the gateway of the `kind` network;
on macOS through `host.containers.internal` (podman) or `host.docker.internal`
(docker), which the VM forwards to the Mac. The script prints the address.

Things to try in one chat:

| ask | expect |
|---|---|
| read `/workspace/src/app.py` with `read_file` | the probe's answer |
| read `/etc/shadow` | a notice: refused by the security policy |
| run `uv sync` | a notice: refused — no Kata, so the site is `container` |
| call `env_config` | the key comes back as `[redacted:aws-access-token]` |
| call `release_notes` | passes; the journal has `payload.injection` with weight 0 |
| call `echo` with an `AKIA…` key in the text | a notice: refused, `payload.leak` |
| a few refusals more | the chat is blocked; its tools are refused from now on, other chats keep theirs |

The journal:

```sh
kubectl -n ads port-forward svc/ads-audit 8082:8082 &
AUDIT='curl -sk -H "authorization: Bearer local-audit-token-32-bytes"'
$AUDIT https://127.0.0.1:8082/audit/events
$AUDIT https://127.0.0.1:8082/audit/conversations/<chat id>/budget
```

The chat id is the session id in the ads URL.

To enforce the injection check instead of recording it, add `review: []` to
`interception.response` in `policy.example.yaml` and rerun the script with
`ADS_SKIP_BUILD=1` (without helm, render `rendered.yaml` again first); the policy
service picks the document up without a restart.

## Also worth trying

- `kubectl -n ads delete pod -l app.kubernetes.io/component=ads-policy`, then keep
  chatting — the run survives, because runs live in Redis.
- `kubectl -n ads scale deploy/ads-audit --replicas=0`, make some calls, watch them
  queue at `kubectl -n ads port-forward svc/ads-rabbitmq 15672:15672` (guest/guest),
  scale back and see the backlog drain.
- `kubectl -n ads scale deploy/ads-injection-scanner --replicas=0` — results still pass
  (the check is in review), and the journal shows `payload.injection.unchecked`.
- `kubectl -n ads scale deploy/ads-mcp-probe-container --replicas=0` — a notice that
  the tool service is unavailable, and the model answers without it.
- Stay silent for five minutes (`policy.runTtlSeconds` is 300) and write again — the
  chat gets a new run with the same conversation label.

## Tear down

```sh
kind delete cluster --name ads     # with podman: KIND_EXPERIMENTAL_PROVIDER=podman first
```
