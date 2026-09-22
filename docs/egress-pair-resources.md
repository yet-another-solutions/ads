# Paired placement and control resource contract

The manager's `pair_objects` builders define the native Kubernetes placement
and control-plane resources for the upcoming four-component pair. These
builders are not yet called by session provisioning. They neither create a
success-returning runtime fake nor claim a working private attachment.

## Identity and placement

`PairBinding` contains manager-owned session, sandbox, project and attachment
generation UUIDs. A generation is distinct from policy revision, egress process
UUID and persistent DNSSEC identity. Service and control-policy selectors match
sandbox, generation and exact component together, not project alone or a
reused private IP address. Stable object names do not authorize adopting a
replacement UID; the lifecycle integration must retain exact object bindings.

Two `scheduling.k8s.io/v1alpha2` PodGroups use `minCount: 2` and hostname
topology: guest VM plus its local relay, and egress VM plus its local relay.
IPC remains outside those groups. The manager must create both groups and all
four compute members before waiting for readiness. The groups need not occupy
the same worker; current lab proof remains single-worker.

The native feature prerequisites were verified with a disposable lab canary.
For Kubernetes v1.36.4, API server needs `GenericWorkload` and
`TopologyAwareWorkloadScheduling`, plus the alpha API runtime configuration.
Scheduler needs those two gates and `GangScheduling`. Controller-manager needs
`GenericWorkload` so its PodGroup protection controller releases terminal/empty
groups. Merely exposing the API or seeing the topology field in OpenAPI is
insufficient: the API server drops gated fields when their feature is disabled.

## Control surfaces

Three ClusterIP Services provide immutable manager-supplied HTTPS targets:
egress configuration/ping and one direct session-health URL for each relay.
The egress relay Service additionally exposes its WireGuard UDP socket.
No Service exposes a NodePort, external address or plaintext control endpoint.

Pair-scoped ingress policies allow HTTPS only from the exact paired IPC
generation. Relay UDP is allowed only from the opposite relay of that same
pair/generation. No namespace-wide peer selector or project-only selector is
used. These policies must coexist with no broader additive allow policy that
would defeat the boundary; that is a rendered-chart and live acceptance gate.

Service endpoint readiness must reflect a configured listening socket, not an
established WireGuard peer. Relay `/health` separately reports bounded session
health for IPC and kubelet liveness after startup allowance. The runtime must
not create a circular dependency where the Service hides the socket until the
peer connects. Kubernetes Pod Ready alone is never the IPC health verdict.

## Remaining integration

This component builds two PodGroups, three Services and three ingress policies.
It does not yet provide egress/relay images, compute Pods, upstream/private
namespaces, peer keys, persistent identity, node attachment, lifecycle CRUD or
egress enforcement. Production provisioning remains on the existing path until
those components are wired with mandatory runtime checks and exact cleanup
ownership. Tests cover native API shape, grouping, generation separation,
same-project foreign-pair control denial selectors and distinct direct URLs.
Live CNI control isolation, transport and application acceptance remain open.
