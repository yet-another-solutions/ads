# Exact compute placement and API removal

The existing pair Kubernetes adapter can resolve the node for the four fixed
bare Pods using their complete recorded UID map. Two complete reads require
the same node and exact names, namespace, role/generation labels and UIDs, with
valid resource versions and without adopting controller-owned Pods. Missing, unassigned,
replaced or split-node members block capture. A failed or terminating Pod still
has placement; neither its status nor the placement result proves runtime state.

Pod deletion requires the exact recorded UID and captured node. Each request
uses the observed UID and resource version as Kubernetes preconditions, with
foreground propagation and no grace-period override. Terminating Pods are only
observed. Conflicts are retried by a future owned lifecycle invocation, never
forced. Replacement identities and changed node placement fail closed.

A successful delete request is not completion. A true adapter result means
only that a subsequent Kubernetes read found the fixed Pod name absent; it is
not runtime release, CNI release, storage reclamation or generation retirement.
Timeouts and non-404 API errors are not absence.

This component has no production teardown caller and does not bypass the
existing lifecycle guard. Ordered teardown must first commit settled-writer
ownership, node admission fencing and the original protected runtime capture.
It must preserve policies, volumes, keys and the journal until independent
positive runtime/storage release is proved. Node-owner delivery and unsupported
partial inventory handling remain separate work.
