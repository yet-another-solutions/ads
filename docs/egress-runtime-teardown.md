# Ordered private-runtime teardown

The normal and recovery lifecycle paths now call an ordered private-runtime
stage after metadata capture and original-writer settlement. This stage returns
positive only after a trusted node-owner report proves release of the original
inventory. It does not retire the pair or drop its cleanup intent.

## Ordering and evidence

- Seal original ownership under the existing exact cleanup claim and creator
  fence. Unresolved original writes block all teardown I/O.
- Capture all six exact bound PVCs before removing Pods: workspace, three CA
  clones, IPC state and persistent egress state. Persist original PV identities,
  CSI volume keys, observed nodes and reclamation-protection facts on PairIntent.
  Workspace and persistent egress state retention remain sticky for idle.
- Resolve all four exact Pod identities to one node. The trusted node-owner
  port must durably fence admission before capturing the original inventory.
  Commit its exact scope/Pod/boot/digest-bound response before deleting compute.
- Remove the four private Pods in guest, egress, guest-relay, egress-relay order,
  with original UID/resourceVersion/node checks. An incomplete API removal stops
  advancement. A lost deletion response retains the journal and can only retry
  the same original identity.
- Obtain a fresh trusted release observation against the committed capture.
  Kubernetes absence alone cannot produce this report. Persist only a positive
  exact-inventory result; blocked observations do not erase earlier captures.

Every external boundary is outside SQL transactions and fenced by short
existing-claim transactions. Claim loss, cancellation, timeout, failed capture
commit, changed scope and competing inventory leave evidence intact. Restarts
reuse original captures rather than trying to reconstruct deleted resources.
The retained positive result is validated under the still-fenced original
writer ledger before reuse.

## Remaining boundaries

`PairNodeOwner` is a narrow trusted delivery port, not a host transport or a
new root-capable API. The production provider deliberately has no node owner
until that separately reviewed integration exists; it returns blocked without
storage/node/delete I/O. Tests fake this unbuilt port, not production success.
Reports must not be accepted from guests, relays, arbitrary HTTP payloads or
untrusted files. The actual node command already enforces protected inventory
and admission-fence ordering; transport must preserve that authority.

Full-pair bound storage and the existing complete node inventory are required.
Earlier partial starts, missing node inventories and unavailable bound-volume
evidence remain fail-closed, not silently synthesized or claimed supported.
IPC Pod teardown, positive storage release/reclamation, exact key/control
cleanup, generation retirement, retained-state transfer and reset coordination
remain later lifecycle stages. This component keeps the final paired-completion
guard and all policies, credentials, PVCs and generation evidence.

The proof here is real PostgreSQL and real Kubernetes-adapter logic with fake
external Kubernetes/CSI and node-owner responses. It is not live integration
acceptance, and does not close slice 19.
