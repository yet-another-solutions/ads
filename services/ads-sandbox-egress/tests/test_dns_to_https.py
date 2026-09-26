"""Real signed DNS publication -> ECH client -> inspected origin -> URL policy."""

import asyncio
import base64
import os
import time

import dns.asyncquery
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from ads_sandbox_egress.dnssec_answer import AnswerAuthentication
from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.dnssec_identity import DNSSECIdentities
from ads_sandbox_egress.dnssec_view import SyntheticDNS
from ads_sandbox_egress.resolver_membership import FreshMembership
from test_certificates import pair_signer as pair_signer
from test_certificates import pair_state as pair_state
from test_connections import connection_lab
from test_dns_transport import transport
from test_dnssec_chain import PARENT, ROOT, PublicDNS
from test_normalization import nginx_helper as nginx_helper
from test_resolution import resolver
from test_tls import anyio_backend as anyio_backend
from test_tls import native as native


@pytest.mark.anyio
async def test_actual_dns_config_drives_ech_and_fresh_membership(
    native, tmp_path, pair_signer, pair_state, nginx_helper
):
    _, directory, executable = native
    origin_name = dns.name.from_text("origin.example.")
    fixture = PublicDNS()
    fixture.data[origin_name, dns.rdatatype.A] = fixture.signed(
        dns.rrset.from_text(origin_name, 60, "IN", "A", "1.1.1.1"), PARENT
    )
    fixture.data[origin_name, dns.rdatatype.HTTPS] = fixture.signed(
        dns.rrset.from_text(
            origin_name, 60, "IN", "HTTPS", "1 . alpn=http/1.1 ech=AAE= ipv4hint=1.1.1.1"
        ),
        PARENT,
    )
    upstream = transport(fixture)
    _, upstream_port = await upstream.start("127.0.0.1", 0)
    frontend_dns = None
    process = None
    try:
        async with connection_lab(
            native,
            tmp_path,
            pair_signer,
            pair_state,
            nginx_helper,
            secure=True,
            protocol="http/1.1",
        ) as (owner, address, ech, requests, sockets, names, _):
            authentication = AnswerAuthentication(
                PositiveChains(resolver(upstream_port=upstream_port), {ROOT: fixture.keys[ROOT]})
            )
            owner.resolver = FreshMembership(authentication)
            identities = DNSSECIdentities(ech.store)
            root = identities.initialize_root()
            view = SyntheticDNS(
                authentication,
                identities,
                root_fingerprint=root.fingerprint,
                ech=ech,
                safe_udp_payload=1232,
            )
            frontend_dns = transport(view)
            _, dns_port = await frontend_dns.start("127.0.0.1", 0)
            response = await dns.asyncquery.tcp(
                dns.message.make_query(origin_name, "HTTPS", want_dnssec=True),
                "127.0.0.1",
                port=dns_port,
                timeout=5,
            )
            assert response.flags & dns.flags.AD
            config = response.answer[0][0].params[5].ech
            assert config != b"\x00\x01"
            assert ech.store.dependency_horizon(ech._current) > time.time()
            calls_before = len(fixture.calls)
            trust = tmp_path / "client-trust.pem"
            trust.write_bytes(pair_signer.certificate.public_bytes(Encoding.PEM))
            process = await asyncio.create_subprocess_exec(
                str(executable),
                "s_client",
                "-connect",
                f"{address[0]}:{address[1]}",
                "-servername",
                "origin.example",
                "-verify_hostname",
                "origin.example",
                "-verify_return_error",
                "-CAfile",
                str(trust),
                "-alpn",
                "http/1.1",
                "-ech_config_list",
                base64.b64encode(config).decode(),
                "-ech_outer_alpn",
                "http/1.1",
                "-quiet",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=dict(os.environ, LD_LIBRARY_PATH=str(directory), OPENSSL_CONF="/dev/null"),
            )
            process.stdin.write(b"GET /allowed HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            await process.stdin.drain()
            async with asyncio.timeout(5):
                header = await process.stdout.readuntil(b"\r\n\r\n")
                assert header.startswith(b"HTTP/1.1 200")
                assert await process.stdout.readexactly(2) == b"ok"
            assert len(requests) == len(sockets) == 1 and names == ["origin.example"]
            assert len(fixture.calls) > calls_before  # no persisted-answer membership shortcut
    finally:
        if process is not None:
            if process.returncode is None:
                process.kill()
            await process.communicate()
        if frontend_dns is not None:
            await frontend_dns.close()
        await upstream.close()
