"""Real TLS and HTTP; only the privileged node helper boundary is a fixture."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import ipaddress
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ads_commons.sandbox.node_release import decode_node_release
from ads_sandbox_manager.node_owner import HttpsNodeOwner, NodeOwnerSettings
from ads_sandbox_manager.pair_objects import PairBinding


@pytest.fixture
def certificates(tmp_path):
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic node channel CA")])
    now = datetime.now(UTC)

    def certificate(key, name, *, ca=False, server=False):
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(root_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), True
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False
            )
        )
        if not ca:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                False,
            )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                False,
            )
        return builder.sign(root_key, hashes.SHA256())

    ca = tmp_path / "ca.pem"
    ca.write_bytes(
        certificate(root_key, root_name, ca=True).public_bytes(serialization.Encoding.PEM)
    )
    values = {"ca": ca}
    for role in ("node", "manager", "foreign"):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = certificate(
            key, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]), server=role == "node"
        )
        key_path, cert_path = tmp_path / (role + ".key"), tmp_path / (role + ".pem")
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        values[role] = (cert_path, key_path)
        values[role + "_pin"] = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
    return SimpleNamespace(**values)


@pytest.fixture
def node(certificates, monkeypatch):
    path = Path(__file__).parents[3] / "services/ads-ptp-tools/ads-node-owner"
    loader = importlib.machinery.SourceFileLoader("node_tls_service", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    service = importlib.util.module_from_spec(spec)
    loader.exec_module(service)
    config = {
        "node": "worker.test",
        "namespace": "sandboxes",
        "network": "private",
        "bind": "127.0.0.1",
        "port": 0,
        "ca": str(certificates.ca),
        "certificate": str(certificates.node[0]),
        "key": str(certificates.node[1]),
        "manager_fingerprints": [certificates.manager_pin],
        "pair": {"attestorConfig": "/platform/attestor", "stateDir": "/state"},
        "ipc": "/platform/ipc",
    }
    calls = []
    boot = str(uuid4())
    pod_uids = [str(uuid4()) for _ in range(4)]

    def helper(name, payload):
        calls.append((name, payload))
        if name == "ads-ptp-retire":
            return {"attachment_admission_fenced": True}
        ipc = name == "ads-ipc-release"
        observed = payload["action"] == "observe"
        result = {
            "schema": "ads-ipc-release-v1" if ipc else "ads-node-release-v1",
            "node": config["node"],
            "namespace": config["namespace"],
            "generation": payload["generation"],
            "sandbox_id": payload["sandbox_id"],
            "boot_id": boot,
            "inventory_sha256": "a" * 64,
            "release_inventory_captured": True,
            "observed_runtime_released": observed,
            "leftovers": None,
        }
        if ipc:
            result.update(pod_uid=payload["pod_uid"], volume_uid=payload["volume_uid"])
            names = [
                "pods",
                "ready_sandboxes",
                "live_containers",
                "process_references",
                "mount_references",
            ]
        else:
            result.update(
                network=config["network"],
                pod_uids=pod_uids,
                attachment_admission_fenced=True,
                generation_retired=False,
            )
            names = [
                "pods",
                "ready_sandboxes",
                "live_containers",
                "journals",
                "host_links",
                "process_namespace_references",
            ]
        if observed:
            result["leftovers"] = dict.fromkeys(names, 0)
        return result

    monkeypatch.setattr(service, "helper", helper)
    server = service.Server(config, service.context(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(
            server=server,
            calls=calls,
            config=config,
            url=f"https://127.0.0.1:{server.server_address[1]}",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def settings(node, certificates, *, client="manager"):
    return NodeOwnerSettings(
        endpoints={"worker.test": node.url},
        namespace="sandboxes",
        network="private",
        ca=certificates.ca,
        certificate=getattr(certificates, client)[0],
        key=getattr(certificates, client)[1],
        timeout=5,
    )


@pytest.mark.anyio
async def test_real_mutual_tls_pair_capture_and_observation(node, certificates):
    config = settings(node, certificates)
    channel = HttpsNodeOwner(config, config.context())
    pair = PairBinding(*(uuid4() for _ in range(4)))
    try:
        capture = decode_node_release(await channel.fence_and_capture(pair, node="worker.test"))
        result = decode_node_release(await channel.observe(capture))
        assert capture.pod_uids == result.pod_uids
        assert result.observed_runtime_released
        assert [name for name, _ in node.calls] == [
            "ads-ptp-retire",
            "ads-ptp-release",
            "ads-ptp-release",
        ]
    finally:
        await channel.close()


@pytest.mark.anyio
async def test_real_tls_ipc_role_uses_original_pod_volume_and_digest(node, certificates):
    from ads_commons.sandbox.ipc_release import decode_ipc_release

    config = settings(node, certificates)
    channel = HttpsNodeOwner(config, config.context())
    pair = PairBinding(*(uuid4() for _ in range(4)))
    pod, volume = uuid4(), uuid4()
    try:
        capture = decode_ipc_release(
            await channel.capture_ipc(
                pair, node="worker.test", pod_uid=str(pod), volume_uid=str(volume)
            )
        )
        result = decode_ipc_release(await channel.observe_ipc(capture))
        assert (result.pod_uid, result.volume_uid) == (pod, volume)
        assert result.observed_runtime_released
        assert all(name == "ads-ipc-release" for name, _ in node.calls)
        assert node.calls[-1][1]["inventory_sha256"] == capture.inventory_sha256
    finally:
        await channel.close()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "fault", ["wrong-client", "no-client", "wrong-server-name", "unknown-node", "wrong-ca"]
)
async def test_real_tls_identity_failures_never_invoke_helpers(node, certificates, fault):
    config = settings(
        node, certificates, client="foreign" if fault == "wrong-client" else "manager"
    )
    context = config.context()
    if fault == "no-client":
        context = ssl.create_default_context(cafile=str(certificates.ca))
    elif fault == "wrong-ca":
        context = ssl.create_default_context(cafile=str(certificates.foreign[0]))
        context.load_cert_chain(*map(str, certificates.manager))
    elif fault == "wrong-server-name":
        config.endpoints["worker.test"] = node.url.replace("127.0.0.1", "localhost")
    channel = HttpsNodeOwner(config, context)
    pair = PairBinding(*(uuid4() for _ in range(4)))
    try:
        with pytest.raises((ValueError, RuntimeError, httpx2.HTTPError, ssl.SSLError)):
            await channel.fence_and_capture(
                pair, node="unknown" if fault == "unknown-node" else "worker.test"
            )
        assert node.calls == []
    finally:
        await channel.close()


@pytest.mark.parametrize(
    "fault", ["path", "duplicate-length", "encoding", "transfer", "json", "large"]
)
def test_authenticated_http_cannot_expand_fixed_request_surface(node, certificates, fault):
    config = settings(node, certificates)
    path = "/execute" if fault == "path" else "/v1/observe"
    body = b'{"invalid":true}'
    headers = [
        f"POST {path} HTTP/1.1",
        "Host: localhost",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
    ]
    if fault == "duplicate-length":
        headers.append(f"Content-Length: {len(body)}")
    elif fault == "encoding":
        headers.append("Content-Encoding: gzip")
    elif fault == "transfer":
        headers.append("Transfer-Encoding: chunked")
    elif fault == "large":
        headers[-1] = "Content-Length: 32769"
    message = ("\r\n".join(headers) + "\r\n\r\n").encode() + body
    with socket.create_connection(node.server.server_address, timeout=2) as connection:
        with config.context().wrap_socket(connection, server_hostname="127.0.0.1") as secured:
            secured.sendall(message)
            received = bytearray()
            while part := secured.recv(4096):
                received.extend(part)
    assert b"503" in bytes(received).split(b"\r\n", 1)[0]
    assert node.calls == []
