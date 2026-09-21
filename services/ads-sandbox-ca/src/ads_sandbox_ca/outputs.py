from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import UUID

from ads_sandbox_ca.certificates import Material

PUBLIC_CERTIFICATE = "trusted-egress-ca.pem"
SIGNING_CHAIN = "signing-chain.pem"
ADDITIONAL_TRUST = "egress-only-trust.pem"
PRIVATE_KEY = "trusted-egress-ca.key"
MANIFEST = "complete.json"


def durable_file(directory: Path, name: str, content: bytes, mode: int) -> None:
    """Exclusive creation, flush data then directory; never overwrite an earlier attempt."""
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_outputs(public: Path, private: Path, material: Material, attempt: UUID) -> None:
    """Both fresh mounted filesystems form one publication unit, completed by Job success."""
    if public.resolve() == private.resolve():
        raise ValueError("public and private outputs must be physically separate")
    for directory in (public, private):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("output must be a real directory")
        if any(path.name != "lost+found" for path in directory.iterdir()):
            raise ValueError("output is not fresh")
    public.chmod(0o755)
    private.chmod(0o700)
    durable_file(public, PUBLIC_CERTIFICATE, material.certificate, 0o644)
    durable_file(public, SIGNING_CHAIN, material.chain, 0o644)
    durable_file(public, ADDITIONAL_TRUST, material.additional_trust, 0o644)
    durable_file(private, PRIVATE_KEY, material.private_key, 0o600)
    common = {
        "format": 1,
        "attempt": str(attempt),
        "sha256": material.fingerprint,
        "not_after": material.not_after,
    }
    # Job completion, not either marker alone, commits the pair. Consumer boot must
    # verify matching manifests/certificate/key before using its read-only clones.
    for directory, role in ((public, "public"), (private, "private")):
        durable_file(
            directory,
            MANIFEST,
            json.dumps({**common, "role": role}, sort_keys=True).encode() + b"\n",
            0o644 if role == "public" else 0o600,
        )
