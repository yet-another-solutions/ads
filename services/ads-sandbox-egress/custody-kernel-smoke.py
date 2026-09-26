"""Disposable real loop/ext4 custody proof, in a PRIVATE mount namespace only."""

import hashlib
import os
import stat
import subprocess
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ads_sandbox_egress.custody import Devices, mounted_custody
from ads_sandbox_egress.dnssec_identity import DNSSECIdentities
from ads_sandbox_egress.identity_store import IdentityStore, StateIdentity, StateUnavailable


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=30).stdout.decode().strip()


def authority(name, depth, issuer=None, issuer_key=None):
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC).replace(microsecond=0)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=depth), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
        .sign(issuer_key or key, hashes.SHA384())
    )
    return cert, key


def main():
    if os.getuid() != 0 or os.readlink("/proc/self/ns/mnt") == os.readlink("/proc/1/ns/mnt"):
        raise RuntimeError("explicit private root mount namespace required")
    run("mount", "--make-rprivate", "/")
    loops, mounted = [], []
    private_dev = False
    with tempfile.TemporaryDirectory(prefix="ads-egress-custody-") as temporary:
        base = Path(temporary)
        try:
            for role in ("state", "public", "private"):
                disk = base / (role + ".img")
                with disk.open("xb") as stream:
                    stream.truncate(64 * 1024**2)
                loops.append(run("losetup", "--find", "--show", str(disk)))
            # /dev changes are local to this namespace, never host device paths.
            device_info = {name: os.stat(name) for name in (*loops, "/dev/null", "/dev/urandom")}
            run("mount", "-t", "tmpfs", "-o", "mode=755,size=1m", "tmpfs", "/dev")
            private_dev = True
            for name, info in device_info.items():
                os.mknod(name, stat.S_IFMT(info.st_mode) | 0o600, info.st_rdev)
            labels = ("/dev/ads-egress-state", "/dev/ads-ca-public", "/dev/ads-ca-private")
            for name, loop in zip(labels, loops, strict=True):
                os.mknod(name, stat.S_IFBLK | 0o600, device_info[loop].st_rdev)
            for role, loop in zip(("public", "private"), loops[1:], strict=True):
                run("mkfs.ext4", "-q", "-m", "0", loop)
                target = base / role
                target.mkdir()
                run("mount", "-t", "ext4", loop, str(target))
                mounted.append(target)
            root, root_key = authority("fixture root", 2)
            parent, parent_key = authority("fixture parent", 1, root, root_key)
            minted, minted_key = authority("fixture minted", 0, parent, parent_key)
            pem = serialization.Encoding.PEM
            attempt, generation = uuid4(), uuid4()
            import json

            public, private = base / "public", base / "private"
            (public / "trusted-egress-ca.pem").write_bytes(minted.public_bytes(pem))
            (public / "signing-chain.pem").write_bytes(
                parent.public_bytes(pem) + root.public_bytes(pem)
            )
            (public / "egress-only-trust.pem").write_bytes(b"")
            (private / "trusted-egress-ca.key").write_bytes(
                minted_key.private_bytes(
                    pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )
            for role, directory in (("public", public), ("private", private)):
                (directory / "complete.json").write_text(
                    json.dumps(
                        dict(
                            format=1,
                            role=role,
                            attempt=str(attempt),
                            sha256=minted.fingerprint(hashes.SHA256()).hex(),
                            not_after=minted.not_valid_after_utc.isoformat(),
                        )
                    )
                )
            os.sync()
            for target in reversed(mounted):
                run("umount", str(target))
            mounted.clear()
            for loop in loops[1:]:
                run("blockdev", "--setro", loop)
            wrapping = os.urandom(32)
            identity = StateIdentity(
                uuid4(),
                uuid4(),
                uuid4(),
                uuid4(),
                str(uuid4()),
                str(uuid4()),
                hashlib.sha256(wrapping).hexdigest(),
            )
            devices = Devices(
                *(Path(name) for name in labels),
                64 * 1024**2,
                identity,
                attempt,
                generation,
                generation,
            )
            first = base / "first"
            first.mkdir(mode=0o700)
            with mounted_custody(devices, first) as custody:
                assert custody.initial
                assert custody.trust.public.certificate == minted
                store = IdentityStore(
                    custody.state_directory, identity, wrapping, capacity=2**20, create=True
                )
                try:
                    anchor = DNSSECIdentities(store).initialize_root().fingerprint
                finally:
                    store.close()
            second = base / "second"
            second.mkdir(mode=0o700)
            with mounted_custody(
                replace(devices, attachment_generation=uuid4()), second
            ) as custody:
                assert not custody.initial
                store = IdentityStore(custody.state_directory, identity, wrapping, capacity=2**20)
                try:
                    assert (
                        DNSSECIdentities(store).root(expected_fingerprint=anchor).fingerprint
                        == anchor
                    )
                finally:
                    store.close()
            rejected = base / "foreign"
            rejected.mkdir(mode=0o700)
            try:
                with mounted_custody(
                    replace(devices, identity=replace(identity, state_id=uuid4())), rejected
                ):
                    raise AssertionError("foreign filesystem adopted")
            except StateUnavailable:
                pass
            assert not any(
                str(base) in line for line in Path("/proc/self/mountinfo").read_text().splitlines()
            )
            print("real block clones, first format, encrypted restart, foreign rejection: passed")
        finally:
            for target in reversed(mounted):
                run("umount", str(target))
            if private_dev:
                run("umount", "/dev")
            for loop in reversed(loops):
                run("losetup", "--detach", loop)
            active = run("losetup", "--list", "--noheadings", "--output", "BACK-FILE")
            assert str(base) not in active
            print("temporary loop devices and mounts removed")


if __name__ == "__main__":
    main()
