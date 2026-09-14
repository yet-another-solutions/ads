# Local cluster

Installing the chart on a throwaway kind or minikube cluster. Everything here exists
because the chart deliberately requires infrastructure it does not install.

## 1. Cluster and images

```sh
kind create cluster --name ads

docker build -f services/ads/Containerfile -t ads:local .
docker build -f services/ads-policy/Containerfile -t ads-policy:local .
docker build -f services/ads-audit/Containerfile -t ads-audit:local .
docker build -f services/ads-egress-controlplane/Containerfile -t ads-egress-controlplane:local .

for image in ads ads-policy ads-audit ads-egress-controlplane; do
  kind load docker-image "$image:local" --name ads
done
```

`values-local.yaml` sets `pullPolicy: Never`, so the node uses what was loaded and
never reaches for GHCR — which matters, because `ads-policy` and `ads-audit` have
never been published there.

## 2. Node label

```sh
NODE=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
kubectl label node "$NODE" ads.io/application-node=true
```

That is all the topology the chart requires. It looks for Kata on its own and finds
none here, so the policy service is told there is no sandbox: runs come out as
`container`, and every capability the matrix grants only at `vm` — `process.exec`,
`db.migrate`, pushing to a feature branch — is unavailable. Which is the truth about
a cluster without Kata.

## 3. cert-manager and the local CA

```sh
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.2/cert-manager.yaml
kubectl -n cert-manager wait --for=condition=Available deploy --all --timeout=180s

kubectl apply -f deploy/local/cert-manager-issuer.yaml
kubectl -n cert-manager wait --for=condition=Ready certificate/ads-local-ca --timeout=120s
```

The pods have to trust the CA that signed each other's certificates, so copy it into
the release namespace. Without this `ads` rejects the policy service certificate and
every decision fails closed:

```sh
kubectl create namespace ads
kubectl -n cert-manager get secret ads-local-ca -o jsonpath='{.data.ca\.crt}' \
  | base64 -d > /tmp/ads-ca.crt
kubectl -n ads create secret generic ads-ca --from-file=ca.crt=/tmp/ads-ca.crt
```

## 4. Redis, RabbitMQ, PostgreSQL

These must exist **before** `helm install`: the chart looks the Services up and
refuses to install if they are missing.

```sh
kubectl apply -n ads -f deploy/local/dependencies.yaml
kubectl -n ads rollout status deploy/ads-redis deploy/ads-rabbitmq deploy/ads-postgres
```

## 5. Install

```sh
helm install ads charts/ads -n ads -f charts/ads/values-local.yaml
kubectl -n ads rollout status deploy/ads deploy/ads-policy deploy/ads-audit
```

## 6. Poke it

```sh
kubectl -n ads port-forward svc/ads-policy 8081:8081 &
kubectl -n ads port-forward svc/ads-audit 8082:8082 &

POLICY='curl -sk -H "authorization: Bearer local-policy-token-32-bytes"'
AUDIT='curl -sk -H "authorization: Bearer local-audit-token-32-bytes"'

$POLICY https://127.0.0.1:8081/policy/version

RUN=$($POLICY -H 'content-type: application/json' -d '{
  "subject":"alice","project":"ads","repo":"yet-another-solutions/ads","env":"dev",
  "workdir":"/workspace","runtime_class_name":"kata-clh",
  "node_labels":{"ads.io/sandbox-node":"true"}}' \
  https://127.0.0.1:8081/policy/runs)
ID=$(echo "$RUN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

# The request claims a Kata placement, but this cluster has none, so the run comes
# back as "container". A claim is not a placement.
echo "$RUN"

# denied three times: the repeat costs a multiple of the first
for _ in 1 2 3; do
  $POLICY -H 'content-type: application/json' -d "{\"run_id\":\"$ID\",\"subject\":\"alice\",
    \"capability\":\"secret.read\",\"resource\":\"ads-client-secret\"}" \
    https://127.0.0.1:8081/policy/decide
done

sleep 2   # the policy service drains its audit buffer once a second
$AUDIT https://127.0.0.1:8082/audit/runs/$ID/budget
```

`-k` skips certificate verification from your machine; inside the cluster the pods do
verify, through the CA mounted in step 3.

Worth trying, because none of it shows up when the services run as single processes:

- `kubectl -n ads delete pod -l app.kubernetes.io/component=ads-policy`, then use the
  same run again — it survives, because runs live in Redis and not in the process.
- `kubectl -n ads scale deploy/ads-audit --replicas=0`, make some decisions, watch
  them pile up in the queue at `kubectl -n ads port-forward svc/ads-rabbitmq
  15672:15672` (guest/guest), then scale back up and see the backlog drain.
- `kubectl -n ads scale deploy/ads-redis --replicas=0` — decisions turn into
  `run.store` denials and `/health/ready` on the policy pod goes 503 while
  `/health/live` stays 200.
- Wait five minutes (`policy.runTtlSeconds` is 300 here) and reuse the run —
  `run.unknown`.

## Tear down

```sh
kind delete cluster --name ads
```
