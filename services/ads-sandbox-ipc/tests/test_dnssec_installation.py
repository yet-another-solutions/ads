import base64
import hashlib
import runpy
import struct
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import uuid4

import msgspec
import pytest

from ads_commons.egress import EgressDNSAnchor
from ads_sandbox_ipc.config import EgressPair
from ads_sandbox_ipc.dnssec_trust import DNSSECInstallation, validate_anchor
from ads_sandbox_ipc.guest import Frame, Pod
from ipc_support import FakeProcess, Harness


def anchor(project, sandbox, key=b"k" * 32):
    return EgressDNSAnchor(
        project,
        sandbox,
        hashlib.sha256(b"\0" + struct.pack("!HBB", 257, 3, 15) + key).hexdigest(),
        "257 3 15 " + base64.b64encode(key).decode(),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("case", ["good", "exit", "stderr", "wrong", "timeout", "pair", "changed"])
async def test_persisted_pin_and_exact_install_proof_before_readiness(tmp_path, case):
    h = Harness(tmp_path, control_seconds=0.05)
    pair = EgressPair(uuid4(), "https://egress.test", ("https://a", "https://b"), uuid4())
    settings = replace(h.settings, egress=pair)
    value = anchor(pair.project_id, settings.sandbox_id)
    transport = AsyncMock()
    transport.anchor.return_value = value
    installer = DNSSECInstallation(settings, transport, h.kube)
    process = FakeProcess()
    if case != "timeout":
        process.frames.put_nowait(
            Frame(
                stdout=(value.fingerprint + "\n").encode() if case != "wrong" else b"wrong",
                stderr=b"bad" if case == "stderr" else b"",
                exit_code=1 if case == "exit" else 0,
            )
        )
    h.kube.start = AsyncMock(return_value=process)
    if case == "pair":
        transport.anchor.return_value = msgspec.structs.replace(value, sandbox_id=uuid4())
    if case == "changed":
        installer.path.write_bytes(
            msgspec.json.encode(anchor(pair.project_id, settings.sandbox_id, b"z" * 32))
        )
    if case == "good":
        await installer.install(h.kube.pod)
        assert process.closed
        assert installer._installed_pod == h.kube.pod
        h.kube.start.assert_awaited_once_with(
            h.kube.pod, ["/usr/local/sbin/ads-sandbox-dnssec"], validate_anchor(value)
        )
        await installer.install(h.kube.pod)
        assert h.kube.start.await_count == 1
        assert msgspec.json.decode(installer.path.read_bytes(), type=EgressDNSAnchor) == value
        restarted = DNSSECInstallation(settings, transport, h.kube)
        changed = Pod(h.kube.pod.name, "replacement")
        transport.anchor.return_value = anchor(pair.project_id, settings.sandbox_id, b"x" * 32)
        with pytest.raises(ValueError, match="changed"):
            await restarted.install(changed)
    else:
        with pytest.raises((ValueError, RuntimeError, TimeoutError)):
            await installer.install(h.kube.pod)
        assert installer._installed_pod is None
        if case in ("pair", "changed"):
            h.kube.start.assert_not_awaited()
        else:
            assert process.closed


@pytest.mark.anyio
async def test_trust_installation_failure_prevents_guest_probe(ipc):
    trust = AsyncMock()
    trust.install.side_effect = RuntimeError("anchor installation failed")
    ipc.guest.trust = trust
    with pytest.raises(RuntimeError, match="anchor installation"):
        await ipc.guest.prepare()
    assert not ipc.kube.calls
    assert ipc.guest.pod is None


@pytest.mark.parametrize("defect", ["none", "fingerprint", "algorithm", "private", "shape"])
def test_actual_inner_installer_exact_public_root_only(tmp_path, defect):
    script = Path(__file__).parents[2] / "ads-sandbox-base/scripts/ads-install-dnssec-anchor"
    install = runpy.run_path(str(script))["install"]
    value = msgspec.to_builtins(anchor(uuid4(), uuid4()))
    if defect == "fingerprint":
        value["fingerprint"] = "a" * 64
    if defect == "algorithm":
        value["dnskey"] = value["dnskey"].replace(" 15 ", " 8 ")
    if defect == "private":
        value["dnskey"] = "-----BEGIN PRIVATE KEY-----"
    if defect == "shape":
        value["extra_trust"] = "forbidden"
    destination = tmp_path / "bind.keys"
    if defect == "none":
        assert (
            install(msgspec.json.encode(value), destination, tmp_path / "delv")
            == value["fingerprint"]
        )
        assert destination.read_text() == (
            'trust-anchors {\n  "." static-key 257 3 15 "'
            + base64.b64encode(b"k" * 32).decode()
            + '";\n};\n'
        )
        assert destination.stat().st_mode & 0o777 == 0o644
    else:
        with pytest.raises(ValueError):
            install(msgspec.json.encode(value), destination, tmp_path / "delv")
        assert not destination.exists()
