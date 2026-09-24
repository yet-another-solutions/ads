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
- Capture the exact manager-owned IPC Pod's application-node placement twice,
  retaining its original UID and resource version alongside the IPC volume
  identity. Commit a separate `ads-ipc-release-v1` node capture before deleting
  IPC with UID/resource-version preconditions and normal grace.
- Observe IPC runtime and mount release against that original application-node
  capture before removing any private compute. A private-pair report cannot
  stand in for IPC proof. API absence is only removal progress. Lost replies
  and manager restart reuse the original retained capture; they do not recapture
  a missing or replaced Pod. Ordinary idle still requires the authenticated,
  transition-bound drain acknowledgement, including at the runtime boundary.
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

`PairNodeOwner` is implemented by the configured mutual-TLS node-owner channel;
see [authenticated delivery](egress-node-delivery.md). Production startup
requires that configuration, and DI supplies/closes the real client. Direct
isolated fixtures without a channel still block before storage/node/delete I/O.
Reports cannot be accepted from guests, relays, arbitrary HTTP payloads or
untrusted files. Fixed server-side helper paths, dedicated TLS authority,
fresh request correlation and original boot/inventory binding preserve the
protected node command's inventory and admission-fence ordering.

Full-pair bound storage and the existing complete node inventory are required.
Earlier partial starts, missing node inventories and unavailable bound-volume
evidence remain fail-closed, not silently synthesized or claimed supported.
The manager IPC stage, strict proof contract, native node inventory/observation
and trusted production delivery are implemented. Repository lifecycle tests
fake external node delivery; separate real TLS tests exercise the delivery
with only privileged helpers faked, and kernel CI exercises the observers.
Neither a digest nor an arbitrary report is authority.
Positive storage release/reclamation, exact key/control cleanup,
generation retirement, retained-state transfer and reset coordination remain
later lifecycle stages. This component keeps the final paired-completion guard
and all policies, credentials, PVCs and generation evidence.

The proof here is real PostgreSQL and real Kubernetes-adapter logic with fake
external Kubernetes/CSI and node-owner responses. It is not live integration
acceptance, and does not close slice 19.
