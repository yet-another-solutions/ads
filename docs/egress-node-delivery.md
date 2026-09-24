# Authenticated node-owner delivery

The manager's `HttpsNodeOwner` implements the private-pair and application-node
IPC release ports. It calls the root-owned `ads-node-owner` service on each
explicitly configured original node. There is no Kubernetes exec, SSH shell,
caller-selected command, helper path, kubeconfig, storage path or arbitrary URL
in this API. The channel does not authorize volume deletion or final generation
retirement.

## Trust boundary

Use a dedicated platform CA and separate server certificate per node, with a
DNS/IP SAN matching that node's configured HTTPS origin. Issue a dedicated
manager client certificate with clientAuth EKU. The node requires both a valid
client chain and the exact SHA-256 DER certificate fingerprint configured by the
platform. At most two fingerprints are accepted for controlled rotation. Do not
reuse guest, relay, service-origin bearer, general web-service or sandbox signer
credentials for this boundary.

The manager verifies server name and the dedicated CA, loads its certificate/key
before accepting application work, disables environment proxies and redirects,
and sends no credentials in JSON. TLS 1.3 is the minimum. Endpoints come only
from platform configuration, keyed by the original node identity; reports from
another node or an unknown endpoint are rejected.

Every request carries a fresh UUID nonce, fixed operation, exact namespace,
network, sandbox/generation, and the original IPC Pod/volume where applicable.
Observation also carries the original boot and inventory digest. The TLS
response must echo the nonce and SHA-256 of the exact request bytes. Strict
report parsing, scope/boot/digest binding, and the manager's retained ownership
journal checks all remain mandatory. Correlation prevents accepting a different
exchange; a digest by itself still provides no authentication.

## Operations and interruption

- `pair-capture`: persist the irreversible CNI admission fence, then invoke the
  existing protected private-pair capture.
- `pair-observe`: observe against the existing protected original inventory.
- `ipc-capture`: capture original application-node IPC runtime and filesystem
  inventory.
- `ipc-observe`: observe that exact IPC capture, without conflating it with the
  private-pair inventory.
- `partial-capture`: fence admission and capture the exact nonempty original
  private role/UID map through `ads-ptp-partial`.
- `partial-observe`: observe that same retained partial inventory, boot and
  digest. The separate partial report cannot satisfy a full four-Pod contract.
- `ipc-storage-capture` / `ipc-storage-observe`: capture the original local IPC
  filesystem identity and positively observe its release and reclamation.
- `block-capture` / `block-observe`: bind original CSI Block backing and kernel
  identities to the existing private runtime capture; observe original mapping,
  mount, process and dependent-device references. See `egress-block-storage.md`.

The service substitutes all configuration paths server-side. Only those fixed
helpers can be executed, without a shell or inherited caller environment.
Requests and responses are limited to 32 KiB; helper reports retain their
stricter 16 KiB manager contract. There are at most four server workers, bounded
TLS/socket waits, an absolute exchange lifetime, and bounded helper subprocess
deadlines. Errors do not return helper stderr, paths, commands or secrets.

Manager timeout, cancellation or lost response is not a fence rollback.
An already-issued helper may finish its protected inventory/fence write. Its
idempotent retry must use the same ownership; a new inventory cannot be invented
after deletion. The existing lifecycle checks ownership before external calls
and again before committing reports. Client shutdown closes transports; server
shutdown never erases protected evidence.

## Installation from CI-built tooling

Run the service as an actual host systemd service, not in a private PID or mount
namespace. Extract the scripts from the reviewed immutable CI-built
`ads-ptp-tools` image. Do not build an image on a lab host. Install the
`ads-ptp`, `ads-ptp-attest`, `ads-ptp-retire`, `ads-ptp-release`,
`ads-ptp-partial`, `ads-ipc-release`, `ads-ipc-storage`, `ads-block-release` and
`ads-node-owner` scripts together in `/usr/local/bin`,
root-owned mode 0755, including protected parent directories.

Use `deploy/node-owner/ads-node-owner.service`. The host must already have the
supported CRI, kubectl, crictl and existing protected observer configurations.
The sample `deploy/node-owner/rbac.yaml` grants only namespaced Pod observation
and PVC reads plus cluster-scoped get-only PV access to a dedicated kubeconfig
identity. Substitute the two named
placeholders explicitly; it is not a cluster-admin bootstrap. The manager gets
no node/PV mutation or pods/exec permission from this channel.

Create `/etc/ads-node-owner/config.json` root-owned mode 0600 with exactly:

```json
{
  "node": "original-node-name",
  "namespace": "sandbox-namespace",
  "network": "configured-cni-network",
  "bind": "observed-private-listener-address",
  "port": 9443,
  "ca": "/etc/ads-node-owner/manager-ca.pem",
  "certificate": "/etc/ads-node-owner/node.pem",
  "key": "/etc/ads-node-owner/node.key",
  "manager_fingerprints": ["64-lowercase-hex-characters"],
  "pair": {
    "attestorConfig": "/etc/ads-ptp/attestor.json",
    "stateDir": "/var/lib/ads-ptp",
    "kubeletRoot": "/var/lib/kubelet"
  },
  "ipc": null
}
```

The displayed names/address/fingerprint are placeholders, not deployment values.
An IPC-only node uses `pair: null` and sets `ipc` to its protected IPC observer
configuration path. A node fulfilling both roles may configure both. Node,
namespace and network must agree with the underlying observer configuration.
Private keys, kubeconfigs and state directories remain outside ordinary
artifacts and source control. Apply host-network access control restricting
this listener to the manager's authorized network; mTLS remains mandatory even
behind that restriction.

## Manager and Helm

`ADS_SANDBOX_MANAGER_NODE_OWNER` is a JSON object with exactly `endpoints`,
`namespace`, `network`, `ca`, `certificate`, `key`, and `timeout`.
Environment startup rejects absent/null/empty or invalid configuration, invalid
TLS files, namespace mismatch, or a timeout not shorter than `control_seconds`.
There is no production opt-out returning success. Direct component fixtures
may omit the channel, in which case the existing teardown remains blocked.

Helm's `sandbox.manager.nodeOwner` carries the nonsecret endpoint map, network,
`timeoutSeconds` and `tlsSecretName`. The pre-provisioned Secret contains
`ca.crt`, `tls.crt`, and `tls.key`, mounted read-only at `/node-owner` only in the
manager. The default 60-second node call fits the 75-second control deadline.
Empty chart defaults cannot start the manager; they are not guessed identities.
No cert-manager signer or private signing key is mounted into the manager.

## Evidence boundary

Tests exercise actual loopback TLS 1.3 and the real node HTTP handler for both
roles, with synthetic CA/certificates and a fake privileged-helper boundary.
They reject wrong or missing client identity, wrong server name, unconfigured
node, altered nonce/request digest, mismatched scope/boot, redirects and excess
response bytes. Separate node-helper tests and kernel CI cover the privileged
observer logic; these are explicit, distinct boundaries.

Live host installation, certificate distribution, workload release,
driver-specific storage reclamation, partial starts, retirement/resume and the
full lifecycle matrix remain separate obligations. Passing this transport
contract is not a claim of live integration or slice-19 completion.
