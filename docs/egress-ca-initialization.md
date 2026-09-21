# Egress CA initialization component

`ads-sandbox-ca` is a one-time runtime data initializer. Its image is built,
tested and published through the existing GitHub Actions matrices, not in the
lab. It does not build an image, rootfs, binary or chart at runtime.

## Inputs and output contract

The manager's normal-runtime Job supplies these immutable inputs:

- `/signer/tls.crt` and `/signer/tls.key`: the explicitly configured existing
  intermediate Secret in the same namespace, mounted read-only. Certificate
  order is signing intermediate through its self-signed root.
- `/additional/ca.crt`: a public-only PEM bundle, possibly empty, captured once
  from the configured additional trust ConfigMap.
- `ADS_CA_ATTEMPT`: the retained Job's UID, not the Pod UID.
- `ADS_CA_BYTES`: the exact integer byte size of each source Block PVC.
- `/dev/ads-ca-public` and `/dev/ads-ca-private`: distinct new whole block
  devices, 64Mi through 1Gi each. The manager default will be 256Mi.

No Kubernetes token or API access is needed by this image. It neither discovers
nor copies Secrets. The root private key is never input; the intermediate key
remains on its read-only Secret mount, never either output disk.

Each hierarchy certificate must be currently valid, permit the new CA depth,
have a valid direct issuer signature, use a supported strong key/hash, and have
CA/signing constraints. Unsupported critical extensions and constrained
name/EKU hierarchies fail closed rather than silently dropping restrictions.
The child uses a fresh P-384 key, critical CA/pathlen:0 and cert/CRL-signing usage.
Its `notAfter` is exactly the signing intermediate's, not a new duration.
An ancestor expiring earlier is rejected.

Public ext4 volume:

- `trusted-egress-ca.pem`: the only newly minted certificate sandbox boot may
  install into trust, alongside its ordinary golden baseline.
- `signing-chain.pem`: public parents, separate from both sandbox trust
  installation and the configurable extra bundle.
- `egress-only-trust.pem`: extra public anchors, imported by egress alone.
- `complete.json`: format, Job attempt UID, minted certificate fingerprint,
  exact expiry and role.

Private ext4 volume:

- `trusted-egress-ca.key`: only the new subordinate key, mode 0600.
- `complete.json`: the same generation, fingerprint and expiry, private role.

The private volume is never cloned or attached to the guest. Consumer clones
must be read-only; matching manifests and certificate/key must be verified at
consumer boot. The unrelated untrusted issuer belongs to each egress process
and is deliberately neither minted nor persisted by this Job.

## Failure and recovery boundary

Preflight checks only the two designated devices. It rejects regular files,
symlinks, partitions, holders, read-only devices, wrong sizes, kernel claims
across mount namespaces, existing signatures and aliased device identities.
It does not enumerate/mknod host disks or assume a Kata-specific disk layout.
Both device checks finish before either format.

New files are exclusively created and fsynced. Both completion manifests are
written only after all certificate/key data; the Job may succeed only after
both filesystems unmount. Neither manifest alone commits the pair. Mount,
write, flush or unmount failure is fatal with a sanitized error class only.
A crash may leave partial output and is never repaired by reformatting it in
place. Manager must retain the Job name lock, prove release of both outputs,
delete the failed pair with UID/resourceVersion guards, and start a new attempt.

This PR supplies the initializer and its existing CI build/publish integration.
The next CA lifecycle change wires the retained Job, paired golden recovery,
Helm inputs, consumer cloning and boot verification. No CA Job has run in the
lab and no integrated trust/read-only acceptance is claimed by these tests.
