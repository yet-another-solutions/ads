# Positive never-scheduled runtime proof

The paired lifecycle distinguishes a sealed, never-dispatched Pod from an
original issued Pod that Kubernetes can prove never reached a node. Neither is
a fabricated node inventory. These facts prove only runtime exclusion, not
volume release, reclamation, control disposition or generation retirement.

## Original identity and admission exclusion

The manager reads the original manager-owned Pod and checks its UID, labels,
namespace, resource version and lack of controller ownership. An empty
`spec.nodeName` is required; an assigned Pod in `Pending` is not equivalent.
Contradictory container/init/ephemeral status or a true PodScheduled condition
is rejected.

The Kubernetes binding implementation atomically refuses a Pod that already
has a deletion timestamp or a node assignment. Pod updates cannot clear an
existing node assignment. These API contracts are the basis of this path,
not a heuristic based on phase or API absence
([binding implementation](https://github.com/kubernetes/kubernetes/blob/master/pkg/registry/core/pod/storage/storage.go),
[Pod update validation](https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/core/validation/validation.go)).

- An original unassigned Pod with an actual deletion timestamp is positive
  admission-exclusion evidence without issuing another DELETE.
- For a non-deleting Pod, the manager commits a retained dispatch reservation
  before one normal foreground DELETE with original UID and resource-version
  preconditions. It requires the actual successful response containing the
  same original unassigned Pod, not a prior GET followed by a 404.
- A scheduler or metadata race is a definitive HTTP 409 rejection, retained
  as such. Only that rejected attempt allows a new exact capture/reservation.
- Timeouts, caller cancellation, a lost response or a 404 never become a
  successful receipt and never authorize replay of an inflight deletion.

Kubernetes returns the deleted Pod for this resource. The generic registry
applies deletion preconditions atomically; the Pod strategy itself handles
the absence of a node assignment. The manager does not request zero grace,
strip finalizers, force deletion, or mutate a node
([registry](https://raw.githubusercontent.com/kubernetes/kubernetes/master/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go),
[Pod deletion strategy](https://raw.githubusercontent.com/kubernetes/kubernetes/master/pkg/registry/core/pod/strategy.go)).

## Retention and cancellation

The permanent creator fence and sealed settled/unissued writer ledger precede
this operation. Each role retains its original capture, dispatch state and
response independently of session/work-row lifetime. The original invocation
can settle after caller or ownership loss but cannot advance the old cleanup
claim. Application shutdown drains outstanding invocations with a bounded
deadline. A retained response cannot change the original UID or be replaced.

IPC is excluded first, then private compute roles in their existing order.
For this path, every issued runtime must be positively unassigned before
deletion begins. A subsequent binding race remains blocked and falls back to
the separately required node-evidence path; it does not turn partial results
into a whole-pair release. Runtime proof can also combine never-dispatched
roles from the creator seal with positive never-scheduled roles.

## Boundary and tests

Already captured node-runtime cleanup continues against its retained node
capture and does not reread absent Pods as a never-scheduled shortcut. A
scheduled or mixed-start prefix still requires positive partial node inventory.
Irrecoverably lost original DELETE responses remain explicitly unresolved;
no timeout-based clearing or fresh invented inventory is added.

Tests exercise all five role adapters, exact conditional deletion, binding
races, already-deleting and finalizer-retained Pods, malformed/wrong identity,
API errors, original-call cancellation, claim/work/session loss, restart,
retained proof tampering and lost-response/404 ambiguity. Repository tests use
real PostgreSQL with only the external Kubernetes interface faked.
