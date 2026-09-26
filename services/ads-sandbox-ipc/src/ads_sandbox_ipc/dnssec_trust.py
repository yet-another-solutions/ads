"""Pin the authenticated public DNSSEC root before first execution readiness."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import struct
from uuid import uuid4

import msgspec

from ads_commons.egress import EgressDNSAnchor
from ads_sandbox_ipc.config import Settings
from ads_sandbox_ipc.egress_transport import HttpsEgressTransport
from ads_sandbox_ipc.guest import Kubernetes, Pod


def validate_anchor(anchor: EgressDNSAnchor) -> bytes:
    fields = anchor.dnskey.split(" ")
    if len(fields) < 4 or fields[:3] != ["257", "3", "15"]:
        raise ValueError("expected ADS Ed25519 root anchor")
    encoded = "".join(fields[3:])
    public = base64.b64decode(encoded, validate=True)
    if len(public) != 32 or base64.b64encode(public).decode() != encoded:
        raise ValueError("invalid public root key")
    fingerprint = hashlib.sha256(b"\0" + struct.pack("!HBB", 257, 3, 15) + public).hexdigest()
    if fingerprint != anchor.fingerprint:
        raise ValueError("public root fingerprint differs")
    return msgspec.json.encode(anchor)


class DNSSECInstallation:
    def __init__(
        self, settings: Settings, transport: HttpsEgressTransport, kube: Kubernetes
    ) -> None:
        if settings.egress is None:
            raise ValueError("paired DNSSEC installation required")
        self.settings, self.transport, self.kube = settings, transport, kube
        self.directory = settings.pid_directory / "dnssec"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "anchor.json"
        self._installed_pod: Pod | None = None

    async def install(self, pod: Pod) -> None:
        if self._installed_pod == pod:
            return
        async with asyncio.timeout(self.settings.control_seconds):
            anchor = await self.transport.anchor()
            pair = self.settings.egress
            assert pair is not None
            if (anchor.project_id, anchor.sandbox_id) != (
                pair.project_id,
                self.settings.sandbox_id,
            ):
                raise ValueError("authenticated anchor pair mismatch")
            data = validate_anchor(anchor)
            if self.path.exists():
                prior = self.path.read_bytes()
                if len(prior) > 16384 or msgspec.json.decode(prior, type=EgressDNSAnchor) != anchor:
                    raise ValueError("stable sandbox anchor changed")
            else:
                temporary = self.directory / (uuid4().hex + ".tmp")
                try:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, self.path)
                    fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                finally:
                    temporary.unlink(missing_ok=True)
            process = await self.kube.start(pod, ["/usr/local/sbin/ads-sandbox-dnssec"], data)
            try:
                output = bytearray()
                while True:
                    frame = await process.read()
                    output.extend(frame.stdout)
                    if len(output) > 256 or frame.stderr:
                        raise RuntimeError("DNSSEC installer unexpected output")
                    if frame.exit_code is not None:
                        if (
                            frame.exit_code != 0
                            or bytes(output) != (anchor.fingerprint + "\n").encode()
                        ):
                            raise RuntimeError("DNSSEC installer did not confirm exact anchor")
                        break
            finally:
                await process.close()
            self._installed_pod = pod
