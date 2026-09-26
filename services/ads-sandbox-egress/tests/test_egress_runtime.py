import asyncio
import ipaddress
import os
import socket
import ssl
from dataclasses import replace
from types import SimpleNamespace

import httpx2
import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from ads_sandbox_egress import runtime
from ads_sandbox_egress.custody import MountedCustody
from ads_sandbox_egress.settings import load_settings
from test_certificates import pair_signer as pair_signer
from test_configuration_receiver import Keys, payload
from test_settings import environment as environment
from test_tls import identity as identity
from test_tls import native as native


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.mark.parametrize("failure", [None, "helper", "dns", "interception", "health", "discovery"])
def test_real_runtime_control_health_and_reverse_cleanup(
    environment, pair_signer, native, tmp_path, monkeypatch, failure
):
    """Fake block/kernel/Keycloak boundaries only; real executable composition,
    SQLite, crypto, NGINX, DNS listeners, interception listener and HTTPS."""
    settings = load_settings(environment, resolv_conf="")
    ports = {free_port() for _ in range(8)}
    assert len(ports) >= 4
    control, proxy, crl, dns = tuple(ports)[:4]
    # Test network is an explicitly named replacement of kernel attachment,
    # not a production option to relax Network's fixed role admission.
    network = SimpleNamespace(
        private_address=ipaddress.IPv4Interface("127.0.0.1/8"),
        guest_address=ipaddress.IPv4Address("127.0.0.2"),
        control_address=ipaddress.IPv4Address("127.0.0.1"),
        private_interface="lo",
        upstream_interface="lo",
        control_port=control,
        proxy_port=proxy,
        crl_port=crl,
        mtu=1340,
    )
    settings = replace(settings, network=network)
    directory = tmp_path / "runtime"
    directory.mkdir(mode=0o700)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    public = SimpleNamespace(
        certificate=pair_signer.certificate,
        pem=b"".join(
            cert.public_bytes(Encoding.PEM)
            for cert in (pair_signer.certificate, *pair_signer.chain)
        ),
    )
    custody = MountedCustody(
        state,
        True,
        SimpleNamespace(
            public=public,
            private_key=pair_signer.private_key,
            signing_chain=pair_signer.chain,
            additional_trust=(),
        ),
    )
    boundary = SimpleNamespace(network=network, check=lambda: True)
    servers, helpers, processes = [], [], []
    original_server, original_helper = runtime.uvicorn.Server, runtime.Helper

    def server(config):
        result = original_server(config)
        servers.append(result)
        return result

    def helper(path):
        result = original_helper(path)
        helpers.append(result)
        return result

    keys = Keys(settings.pair.ipc_service_subject)

    async def verifier(settings):
        if failure == "discovery":
            raise RuntimeError("injected partial startup failure")
        return keys.verifier  # Named external JWKS, real signature/claim validation.

    start = runtime.DNSTransport.start

    async def dns_start(self, host, port):
        assert port == 53
        return await start(self, host, dns)

    monkeypatch.setattr(runtime.uvicorn, "Server", server)
    monkeypatch.setattr(runtime, "Helper", helper)
    monkeypatch.setattr(runtime, "verifier", verifier)
    monkeypatch.setattr(runtime.DNSTransport, "start", dns_start)
    helper_start = original_helper.start

    async def start_helper(self):
        await helper_start(self)
        processes.append(self.process)
        if failure == "helper":
            raise RuntimeError("injected partial startup failure")

    monkeypatch.setattr(original_helper, "start", start_helper)
    if failure in ("dns", "interception", "health"):
        owner, method = {
            "dns": (runtime.DNSTransport, "start"),
            "interception": (runtime.Interception, "start"),
            "health": (runtime.EnforcementHealth, "healthy"),
        }[failure]
        original = getattr(owner, method)

        async def fail_after_start(self, *args):
            await original(self, *args)
            raise RuntimeError("injected partial startup failure")

        monkeypatch.setattr(owner, method, fail_after_start)
    cert, key, context = runtime.tls_files(settings, directory)

    async def run():
        task = asyncio.create_task(
            runtime.serve(settings, custody, directory, native[0], boundary, cert, key, context)
        )
        try:
            async with asyncio.timeout(10):
                while not servers or not servers[0].started:
                    if task.done():
                        await task
                    await asyncio.sleep(0.01)
            process = helpers[0].process
            verify = ssl.create_default_context(cadata=settings.tls_certificate.decode())
            # Fixture identity has DNS SAN, but this external test address
            # intentionally uses loopback. Disable hostname check only here.
            verify.check_hostname = False
            async with httpx2.AsyncClient(verify=verify, trust_env=False, timeout=2) as client:
                result = await client.get(f"https://127.0.0.1:{control}/ping")
                assert result.status_code == 200 and result.json()["healthy"] is True
                denied = await client.put(
                    f"https://127.0.0.1:{control}/configuration", content=b"{}"
                )
                assert denied.status_code == 401
                headers = {"Authorization": "Bearer " + keys.token()}
                applied = await client.put(
                    f"https://127.0.0.1:{control}/configuration",
                    content=payload(settings.pair, 2),
                    headers=headers,
                )
                assert applied.status_code == 200
                assert applied.json()["instance_id"] == result.json()["instance_id"]
                assert applied.json()["revision"] == 2
                anchor = await client.get(
                    f"https://127.0.0.1:{control}/dnssec-anchor", headers=headers
                )
                assert anchor.status_code == 200
                assert anchor.json()["sandbox_id"] == str(settings.pair.sandbox_id)
                assert set(anchor.json()) == {"project_id", "sandbox_id", "fingerprint", "dnskey"}
                stale = await client.put(
                    f"https://127.0.0.1:{control}/configuration",
                    content=payload(settings.pair, 1),
                    headers=headers,
                )
                assert stale.status_code == 409
                invalid = await client.put(
                    f"https://127.0.0.1:{control}/configuration",
                    content=payload(settings.pair, 0),
                    headers=headers,
                )
                assert invalid.status_code == 400
                process.terminate()
                await asyncio.to_thread(process.wait, 2)
                unhealthy = await client.get(f"https://127.0.0.1:{control}/ping")
                assert unhealthy.status_code == 503 and unhealthy.json()["healthy"] is False
        finally:
            if servers:
                servers[0].should_exit = True
            async with asyncio.timeout(10):
                await task

    if failure:
        with pytest.raises(RuntimeError, match="injected partial startup failure"):
            asyncio.run(run())
    else:
        asyncio.run(run())
    assert helpers[0].process is None
    assert processes
    for process in processes:
        assert process.poll() is not None
        with pytest.raises(ProcessLookupError):
            os.kill(process.pid, 0)
    for port in (control, proxy, crl, dns):
        with socket.socket() as probe:
            assert probe.connect_ex(("127.0.0.1", port)) != 0
    # DNS UDP must also release its socket, and encrypted state must no longer
    # be held by the exited owner after any partial-start failure.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", dns))
    recovered = runtime.IdentityStore(
        custody.state_directory,
        settings.devices.identity,
        settings.wrapping_key,
        capacity=settings.devices.state_bytes // 2,
    )
    recovered.close()
