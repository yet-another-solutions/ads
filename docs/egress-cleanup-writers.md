# Whole-pair writer settlement

The existing cleanup snapshot now retains the original creator owner and exact
claim timestamp, plus every control and compute dispatch marker. A cleanup
claim cannot substitute another creator or regress dispatch evidence.
The existing permanent creator fence remains the dispatch-admission barrier.

After metadata-only capture, `PairCleanupCapture.capture` returns whether all
recorded writers are settled or never issued. This result is deliberately not
runtime quiescence, storage release, deletion authority or generation retirement.
Normal lifecycle and recovery preserve unresolved work and stop at this gate.
Even a true result still encounters the separate runtime-release guard.

## Positive and negative evidence

The check executes under the current original cleanup/recovery claim and locks
the retained PairIntent and any anchored persistent EgressState. It validates
captured immutable identity/payload fields before evaluating all eight controls,
four compute Pods, both relay input Secrets, paired-key custody, four workspace/CA
claims, IPC PVC/Deployment, persistent wrapping key/PVC and topic preparation.

For resources, a settled original dispatch requires an exact bound or separately
captured UID. An unissued dispatch requires no UID. Topic preparation requires
settled or unissued, never inflight. A captured UID cannot settle a writer.
An original publisher may settle an earlier inflight marker after the creator
fence; the cleanup snapshot remains unchanged and is checked against the
monotonic original ledger. Cleanup does not modify any dispatch marker.

Timeout, cancellation, process loss, successful drain, complete UID inventory
and repeated API absence are not settlement. No automatic force-clear,
regeneration, record removal or fallback is added. A never-dispatched generation
can have no outstanding writer, but that alone cannot retire it.

## Remaining lifecycle requirements

The next ordered executor must recheck this claim/fence gate before external
actions, durably fence node admission, capture exact runtime identity before
compute deletion and preserve control policies through positive runtime release.
Storage release/reclamation, retained-state transfer and final retirement remain
separate requirements. Supported live transport/data-plane proof remains outside
this code/CI component boundary.
