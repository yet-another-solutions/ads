# Never-dispatched runtime evidence

Early paired creation may stop before any Pod dispatch. Cleanup now records
that positive fact instead of demanding fictitious bound-volume, CRI or CNI
inventories for a runtime that the manager never created.

## Authority and retention

`LifecycleRepository.seal_pair_cleanup` first verifies the exact cleanup claim,
permanently fences the original creator and requires every original writer to
be either unissued without a UID or normally settled with its exact captured
UID. An inflight invocation, including an ambiguous control, volume or topic
write, prevents sealing. API absence cannot settle it.

The retained journal adds `runtime_unissued`, an ordered list of original
compute resource keys and, independently, `Pod/ipc`. A key qualifies only when
the creator dispatch is explicitly `unissued` and its original UID is null.
IPC also requires the unissued payload to be null. On every retained-journal
read the list is revalidated against both the immutable captured ownership and
the sealed creator snapshot. Missing, additional or duplicate roles, loss of
the fence, changed dispatch and changed UID fail closed.

The evidence survives deletion of the session or cleanup-work row on the
existing non-cascading PairIntent. It does not let the obsolete cleanup claim
continue after that deletion. A new valid owner must still acquire cleanup
authority through the established repository path.

## Runtime boundary

When all four private compute roles and IPC are proven never dispatched,
`PairRuntimeTeardown` can complete its runtime stage without node, storage or
deletion calls. It does not construct a `NodeReleaseReport` or
`IpcReleaseReport`, fabricate an empty kernel inventory, inspect absent Pods,
or claim that an unbound PVC has been reclaimed.

Control-only and volume/topic-only prefixes use this path. Existing resources,
including pending PVCs, remain intact for the later exact-disposition stage.
The original ledger permanently prevents a late publisher from dispatching a
Pod after proof has been committed. A null UID after dispatch does not qualify.

This increment does not yet complete mixed/one-sided runtime states, scheduled
but never-started Pods, node-reboot recovery, storage reclamation or final
generation retirement. Those remain separate evidence obligations. The
paired final-completion guard remains unchanged. No schema migration/backfill
or actual reset is performed; existing incompatible retained journal shapes
are rejected rather than silently upgraded.

## Proof

`test_pair_unissued_runtime.py` exercises real PostgreSQL repositories and
creator fences with external Kubernetes/broker calls faked at their existing
adapter boundaries. Positive early prefixes, retained restart/cascade,
stale claims, dispatch ambiguity and proof tampering are covered. Existing
full-runtime capture/deletion/observation tests remain required, including
their refusal to treat API absence as runtime release.
