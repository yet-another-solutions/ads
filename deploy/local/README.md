# Local cluster

The whole chain on a throwaway kind cluster: browser → ads → Kafka → engine → your
LLM → guardrail → session sandbox, with the policy service, the injection scanner and
the audit journal, all over TLS from a local CA and signed in through Keycloak.

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
building and loading the images on a rerun. A rerun restarts every workload the chart
runs, so the images just built and any changed settings are what serves, and restarts
Keycloak when its realm changed, since Keycloak imports the realm only when it starts;
the other dependencies keep their data. At the end the script prints what is left to
do by hand: `/etc/hosts`, three port-forwards, the LLM, and where to log in.

What it does, in order:

1. **kind cluster** `ads` (`ADS_KIND_CLUSTER` to change), and the thirteen images built
   as `localhost/<name>:local` and loaded into it — `values-local.yaml` sets
   `pullPolicy: Never`. The guest and golden images are not built: no session ever
   starts here, so nothing pulls them.
2. **Node label** `ads.io/application-node=true`. There is no Kata and no sandbox
   node, so the policy service is told there is no sandbox: nothing reaches level
   `vm`, and `process.exec` is refused — including the sandbox's own `exec_shell` and
   `exec_python`.
3. **cert-manager** and a local CA (`cert-manager-issuer.yaml`). The CA is copied into
   the namespace as `ads-ca`; every pod mounts it and trusts the others and Keycloak.
4. **Kyverno** (`ADS_KYVERNO_VERSION`, v1.13.2 by default). The chart ships the exec
   policy and its RBAC and refuses to install without an admission controller to
   enforce them.
5. **Sandbox prerequisites kind has none of**: StorageClasses `local-path` and
   `sandbox-block` over kind's local-path provisioner, and a stub RuntimeClass
   `kata-qemu-ads` carrying `ads.io/runtime-contract=nested-v1`. The stub only gets
   the install past the chart's check — it is `runc`, and no node is labelled as a
   sandbox node, so no run is ever placed in a VM.
6. **Namespace `ads`**, created with the release's ownership metadata so the chart
   adopts it. The dependencies live there and the chart looks them up before it
   installs, but the chart owns the namespace; this is how both can be true.
7. **Redis, RabbitMQ, PostgreSQL, Kafka** (`dependencies.yaml`). PostgreSQL creates
   `ads`, `ads_audit`, `ads_engine`, `ads_preferences`, `ads_sandbox_mcp` and
   `ads_sandbox_manager`.
8. **Keycloak** (`keycloak.yaml`): realm `ads`, user `alice` / `alice`, auditor
   `audrey` / `audrey` (role `auditor`, the `ads-audit` client, and the `ads-audit-ads`
   scope through which the auditor's pages read a chat in ads), and the clients
   the chain exchanges tokens between — `ads` → `ads-engine`, `ads-preferences`;
   `ads-engine` → `ads`, the context services and `ads-guardrail`, each by its own
   client scope; `ads-guardrail` → `ads-sandbox-mcp`, which is how the guardrail
   reaches the sandbox as the person without carrying their own token upstream.
9. **CoreDNS** rewrites `keycloak.ads.local` to the Keycloak Service. Browsers and pods
   then use the same address, `https://keycloak.ads.local:8444`, and the issuer in a
   token is the same wherever it is checked.
10. **The chart** with `values-local.yaml` and `policy.example.yaml` as
    `policy.document` — the built-in rules; through helm, or as `rendered.yaml` when
    there is no helm. The release record goes to `default`; the chart creates and owns
    `ads` and `ads-sandbox`. Guardrail and scanner are on, and the engine reaches the
    sandbox through the guardrail. The audit budget is 12, so a few refusals are enough
    to see a chat lose its tools.

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
| anything at all | an answer: the tools are offered through the guardrail before the model is asked |
| to run anything in the sandbox (`exec_shell`) | a notice: refused — the call went through the guardrail, which decided it at `mcp:sandbox`, and without Kata that site is not a VM |
| a few refusals more | the chat is blocked; its tools are refused from now on, other chats keep theirs |

The refusal is the whole governed path in one line: engine → guardrail → policy →
journal, with the sandbox never reached. The policy decides before the payload is
read, so the secret and injection checks have nothing to see here. A successful
`exec_shell` needs Kata, which this cluster cannot have; to watch the refusal being
made rather than inferred:

```sh
kubectl -n ads logs deploy/ads-guardrail | grep 'tool call refused'
```

The journal:

```sh
kubectl -n ads port-forward svc/ads-audit 8082:8082 &
AUDIT='curl -sk -H "authorization: Bearer local-audit-token-32-bytes"'
$AUDIT https://127.0.0.1:8082/audit/events
$AUDIT https://127.0.0.1:8082/audit/conversations/<chat id>/budget
```

The chat id is the session id in the ads URL.

## Also worth trying

- `kubectl -n ads delete pod -l app.kubernetes.io/component=ads-policy`, then keep
  chatting — the run survives, because runs live in Redis.
- `kubectl -n ads scale deploy/ads-audit --replicas=0`, make some calls, watch them
  queue at `kubectl -n ads port-forward svc/ads-rabbitmq 15672:15672` (guest/guest),
  scale back and see the backlog drain.
- Stay silent for five minutes (`policy.runTtlSeconds` is 300) and write again — the
  chat gets a new run with the same conversation label.

## Tear down

```sh
kind delete cluster --name ads     # with podman: KIND_EXPERIMENTAL_PROVIDER=podman first
```
