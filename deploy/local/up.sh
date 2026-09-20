#!/usr/bin/env bash
# The whole chain on a throwaway kind cluster: browser → ads → Kafka → engine → LLM →
# guardrail → MCP probe, with policy, the injection scanner and the audit journal.
# Safe to run again: every step checks or applies rather than creates blindly.
#
#   bash deploy/local/up.sh
#
# Needs kind, kubectl, podman or docker, and internet access for the images and the
# scanner's model. With helm the chart is installed from source; without it
# deploy/local/rendered.yaml is applied. Works on Linux and macOS.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLUSTER="${ADS_KIND_CLUSTER:-ads}"
# Workloads live in ads and ads-sandbox, both created and owned by the chart; the
# release record itself goes to default, which the chart refuses to share with them.
NAMESPACE=ads
RELEASE_NAMESPACE=default
KYVERNO_VERSION="${ADS_KYVERNO_VERSION:-v1.13.2}"
IMAGES=(
  ads ads-policy ads-audit ads-engine ads-egress-controlplane ads-preferences
  ads-guardrail ads-injection-scanner ads-mcp-probe
  ads-sandbox-mcp ads-sandbox-ipc ads-sandbox-manager
)
if [ -z "${ADS_CONTAINER_ENGINE:-}" ]; then
  if command -v podman >/dev/null; then ADS_CONTAINER_ENGINE=podman; else ADS_CONTAINER_ENGINE=docker; fi
fi
ENGINE="$ADS_CONTAINER_ENGINE"
if [ "$ENGINE" = podman ]; then
  export KIND_EXPERIMENTAL_PROVIDER=podman
fi
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step() { printf '\n==> %s\n' "$*"; }

step "kind cluster ${CLUSTER} (${ENGINE})"
if ! kind get clusters | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER"
fi
kubectl config use-context "kind-${CLUSTER}"

step "images"
if [ "${ADS_SKIP_BUILD:-}" != "1" ]; then
  for image in "${IMAGES[@]}"; do
    "$ENGINE" build -f "services/${image}/Containerfile" -t "localhost/${image}:local" .
    "$ENGINE" save -o "$WORK/image.tar" "localhost/${image}:local"
    kind load image-archive "$WORK/image.tar" --name "$CLUSTER"
    rm -f "$WORK/image.tar"
    if [ "${ADS_FREE_IMAGES:-}" = "1" ]; then
      "$ENGINE" rmi "localhost/${image}:local"
    fi
  done
fi

step "node label"
for node in $(kubectl get nodes -o name); do
  kubectl label --overwrite "$node" ads.io/application-node=true
done

step "cert-manager and the local CA"
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.2/cert-manager.yaml
kubectl -n cert-manager wait --for=condition=Available deploy --all --timeout=300s
until kubectl apply -f deploy/local/cert-manager-issuer.yaml; do
  echo "cert-manager webhook not ready yet"
  sleep 5
done
kubectl -n cert-manager wait --for=condition=Ready certificate/ads-local-ca --timeout=120s

step "Kyverno, which the chart's exec policy needs (it ships the policy, not the engine)"
kubectl apply -f "https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION}/install.yaml"
kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=300s

step "sandbox prerequisites kind does not have: StorageClasses and a stub RuntimeClass"
# No Kata here. The stub only satisfies the chart's install check; without a node
# carrying the sandbox label nothing is ever assigned isolation level vm, and the
# policy service is told so.
kubectl apply -f - <<'PREREQ'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-path
provisioner: rancher.io/local-path
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: sandbox-block
provisioner: rancher.io/local-path
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-qemu-ads
  annotations:
    ads.io/runtime-contract: nested-v1
handler: runc
PREREQ

step "namespace ${NAMESPACE}, handed to the chart"
# The dependencies must exist before the chart is installed — its prerequisite check
# looks them up — but the chart owns the namespace they live in. Create it with the
# release's ownership metadata so helm adopts it instead of refusing.
kubectl apply -f - <<NS
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
  labels:
    app.kubernetes.io/managed-by: Helm
  annotations:
    meta.helm.sh/release-name: ads
    meta.helm.sh/release-namespace: ${RELEASE_NAMESPACE}
NS

CA_FILE="${TMPDIR:-/tmp}/ads-local-ca.crt"
kubectl -n cert-manager get secret ads-local-ca -o jsonpath='{.data.ca\.crt}' | base64 --decode > "$CA_FILE"
kubectl -n "$NAMESPACE" create secret generic ads-ca --from-file=ca.crt="$CA_FILE" \
  --dry-run=client -o yaml | kubectl apply -f -

step "Redis, RabbitMQ, PostgreSQL, Kafka, Keycloak"
kubectl apply -n "$NAMESPACE" -f deploy/local/dependencies.yaml
kubectl apply -n "$NAMESPACE" -f deploy/local/keycloak.yaml
kubectl -n "$NAMESPACE" rollout status deploy/ads-redis deploy/ads-rabbitmq \
  deploy/ads-postgres deploy/ads-kafka --timeout=300s
kubectl -n "$NAMESPACE" rollout status deploy/keycloak --timeout=600s

step "CoreDNS: keycloak.ads.local resolves to the Keycloak Service inside the cluster"
kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' > "$WORK/Corefile"
if ! grep -q 'keycloak.ads.local' "$WORK/Corefile"; then
  awk -v rule="rewrite name keycloak.ads.local keycloak.${NAMESPACE}.svc.cluster.local" '
    { print }
    /^[[:space:]]*ready$/ { match($0, /^[[:space:]]*/); print substr($0, 1, RLENGTH) rule }
  ' "$WORK/Corefile" > "$WORK/Corefile.new"
  kubectl -n kube-system create configmap coredns --from-file=Corefile="$WORK/Corefile.new" \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n kube-system rollout restart deploy/coredns
  kubectl -n kube-system rollout status deploy/coredns --timeout=120s
fi

if command -v helm >/dev/null; then
  step "ads chart, with the example policy (built-in rules plus the probe's bindings)"
  {
    echo "policy:"
    echo "  document:"
    sed 's/^/    /' charts/ads/policy.example.yaml
  } > "$WORK/policy-values.yaml"
  helm upgrade --install ads charts/ads -n "$RELEASE_NAMESPACE" \
    -f charts/ads/values-local.yaml -f "$WORK/policy-values.yaml" \
    --wait --timeout 15m
else
  step "ads chart, already rendered (no helm here)"
  # Every object names its own namespace, so this is applied without one.
  kubectl apply -f deploy/local/rendered.yaml
  kubectl -n "$NAMESPACE" wait --for=condition=Available deploy --all --timeout=900s
fi

if [ "$(uname -s)" = Darwin ]; then
  # The engine runs in a VM; its own name for the Mac forwards to the Mac's localhost.
  if [ "$ENGINE" = podman ]; then LLM_HOST=host.containers.internal; else LLM_HOST=host.docker.internal; fi
else
  if [ "$ENGINE" = podman ]; then
    GATEWAY_FORMAT='{{range .Subnets}}{{.Gateway}} {{end}}'
  else
    GATEWAY_FORMAT='{{range .IPAM.Config}}{{.Gateway}} {{end}}'
  fi
  LLM_HOST="$("$ENGINE" network inspect kind --format "$GATEWAY_FORMAT" 2>/dev/null \
    | tr ' ' '\n' | grep -m1 '\.' || true)"
fi
LLM_URL="http://${LLM_HOST:-<kind network gateway>}:11434/v1"

cat <<EOF

==> Ready.

1. Once, in /etc/hosts:
     127.0.0.1 ads.local keycloak.ads.local

2. In two terminals:
     kubectl -n ${NAMESPACE} port-forward svc/ads 8443:8080
     kubectl -n ${NAMESPACE} port-forward svc/keycloak 8444:8444

   The certificates are signed by the local CA in ${CA_FILE}. Import it into the
   browser, or accept the warning for both addresses.

3. A model that can call tools, on this machine, listening beyond localhost:
     OLLAMA_HOST=0.0.0.0 ollama serve
     ollama pull qwen2.5:7b

   Check that pods reach it (any JSON back is fine):
     kubectl -n ${NAMESPACE} run llm-check --rm -it --restart=Never \\
       --image=curlimages/curl -- curl -s ${LLM_URL}/models

4. https://ads.local:8443 — log in as alice / alice, Settings → Models → Add new model:
     Type:        openai-stream
     Model name:  qwen2.5:7b
     URL:         ${LLM_URL}
     Token:       anything, e.g. ollama

5. Ask it to use the probe, for example:
     "Вызови probe-container__read_file с path /workspace/src/app.py"  — allowed
     "Вызови probe-container__read_file с path /etc/shadow"            — refused, notice
     "Вызови probe-container__run_command с command uv sync"           — refused: no Kata
     "Вызови probe-container__env_config"                              — the key comes back cut out
     "Вызови probe-container__release_notes"                           — journalled, passed on
   A few refusals in one chat and the chat loses its tools (budget 12).

6. The journal:
     kubectl -n ${NAMESPACE} port-forward svc/ads-audit 8082:8082
     curl -sk -H 'authorization: Bearer local-audit-token-32-bytes' \\
       https://127.0.0.1:8082/audit/events | python3 -m json.tool

Tear down: ${KIND_EXPERIMENTAL_PROVIDER:+KIND_EXPERIMENTAL_PROVIDER=podman }kind delete cluster --name ${CLUSTER}
EOF
