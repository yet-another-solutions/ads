"""Single executable owner of custody, enforcement and the HTTPS control plane."""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import sys
import tempfile
from contextlib import AsyncExitStack, ExitStack
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx2
import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization

from ads_commons.egress import EgressDNSAnchor
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_sandbox_egress.app import create_app
from ads_sandbox_egress.certificate_mirror import CertificateMirror
from ads_sandbox_egress.certificate_validation import CertificateValidator
from ads_sandbox_egress.certificates import CertificatePairs, EgressSigner
from ads_sandbox_egress.configuration import PolicyStore
from ads_sandbox_egress.connections import Connections, InterfaceConnector
from ads_sandbox_egress.crl import CRLRepository
from ads_sandbox_egress.crl_http import LocalCRLService
from ads_sandbox_egress.custody import MountedCustody, mounted_custody
from ads_sandbox_egress.dns_transport import DNSTransport
from ads_sandbox_egress.dnssec_answer import AnswerAuthentication
from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.dnssec_identity import DNSSECIdentities
from ads_sandbox_egress.dnssec_view import SyntheticDNS
from ads_sandbox_egress.ech_lifecycle import ECHLifecycle
from ads_sandbox_egress.health import EnforcementHealth
from ads_sandbox_egress.helper import Helper
from ads_sandbox_egress.identity_store import IdentityStore
from ads_sandbox_egress.interception import Interception, KernelBoundary
from ads_sandbox_egress.issuers import untrusted_issuer
from ads_sandbox_egress.origin_tls import OriginContext
from ads_sandbox_egress.resolution import UpstreamResolver
from ads_sandbox_egress.resolver_membership import FreshMembership
from ads_sandbox_egress.runtime_identity import root_identity
from ads_sandbox_egress.settings import PREFIX, Settings, https_url, load_settings
from ads_sandbox_egress.status_acquisition import StatusAcquisition
from ads_sandbox_egress.tls import TLSLibrary

_PEM = serialization.Encoding.PEM


def tls_files(settings: Settings, directory: Path) -> tuple[Path, Path, ssl.SSLContext]:
    paths = (directory / "control.crt", directory / "control.key")
    for path, data in zip(paths, (settings.tls_certificate, settings.tls_key), strict=True):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(paths[0]), str(paths[1]))
    return *paths, context


async def verifier(settings: Settings) -> JwtVerifier:
    context = ssl.create_default_context()
    if settings.ca_bundle:
        context.load_verify_locations(cadata=settings.ca_bundle.decode("ascii"))
    async with (
        asyncio.timeout(10),
        httpx2.AsyncClient(
            timeout=5, verify=context, trust_env=False, follow_redirects=False
        ) as client,
    ):
        async with client.stream("GET", settings.discovery) as response:
            if response.status_code != 200:
                raise RuntimeError("control discovery unavailable")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > 65536:
                    raise RuntimeError("control discovery too large")
    import json

    value: Any = json.loads(data)
    if not isinstance(value, dict) or value.get("issuer") != settings.issuer:
        raise RuntimeError("control discovery issuer mismatch")
    uri = https_url(value.get("jwks_uri", ""))
    if urlsplit(uri).netloc != urlsplit(settings.issuer).netloc:
        raise RuntimeError("control JWKS origin mismatch")
    config = JwtVerifierSettings(
        settings.issuer, "ads-sandbox-egress", "ads-sandbox-egress", uri, context
    )
    return JwtVerifier(config, jwt.PyJWKClient(uri, ssl_context=context, timeout=5))


async def serve(
    settings: Settings,
    custody: MountedCustody,
    directory: Path,
    library: TLSLibrary,
    boundary: KernelBoundary,
    control_cert: Path,
    control_key: Path,
    control_tls: ssl.SSLContext,
) -> None:
    """All native TLS and SQLite work stays on the owning main event-loop thread."""
    async with AsyncExitStack() as cleanup:
        policies = PolicyStore()
        state = IdentityStore(
            custody.state_directory,
            settings.devices.identity,
            settings.wrapping_key,
            capacity=settings.devices.state_bytes // 2,
            create=custody.initial,
        )
        cleanup.callback(state.close)
        root = root_identity(state, initial=custody.initial)
        trust = custody.trust
        signer = EgressSigner.load(
            trust.public.certificate.public_bytes(_PEM),
            trust.private_key.private_bytes(
                _PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
            tuple(cert.public_bytes(_PEM) for cert in trust.signing_chain),
        )
        import time

        ech = ECHLifecycle(
            state,
            library,
            public_name=settings.enforcement.ech_public_name,
            handshake_window=10,
            now=time.time(),
            initialize=custody.initial,
        )
        cleanup.callback(ech.close)
        origin = OriginContext(
            library, extra_trust=tuple(cert.public_bytes(_PEM) for cert in trust.additional_trust)
        )
        cleanup.callback(origin.close)
        helper = Helper(directory / "helper")
        cleanup.push_async_callback(helper.close)
        await helper.start()
        crls = CRLRepository(state)
        crl_service = LocalCRLService(crls, settings.network.guest_address)
        cleanup.push_async_callback(crl_service.close)
        local_crl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            local_crl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            local_crl.bind((str(settings.network.private_address.ip), settings.network.crl_port))
            local_crl.setblocking(False)
            await crl_service.start(local_crl)
        except BaseException:
            local_crl.close()
            raise
        location = crl_service.url(signer.fingerprint)
        pairs = CertificatePairs(state, signer, location)
        mirror = CertificateMirror(
            signer,
            untrusted_issuer(signer.certificate.not_valid_after_utc),
            CertificateValidator(library, trust.public.pem),
            location,
            crls=crls,
        )
        upstream = UpstreamResolver(settings.enforcement.resolver)
        authentication = AnswerAuthentication(
            PositiveChains(upstream, settings.enforcement.anchors)
        )
        payload = min(1232, settings.network.mtu - 28)
        view = SyntheticDNS(
            authentication,
            DNSSECIdentities(state),
            root_fingerprint=root.fingerprint,
            ech=ech,
            safe_udp_payload=payload,
        )
        dns = DNSTransport(
            view,
            sandbox_id=settings.pair.sandbox_id,
            instance_id=policies.instance_id,
            classifier_version=settings.enforcement.destinations.inventory_version,
            safe_udp_payload=payload,
        )
        cleanup.push_async_callback(dns.close)
        await dns.start(str(settings.network.private_address.ip), 53)
        connections = Connections(
            policies,
            settings.enforcement.destinations,
            FreshMembership(authentication),
            helper.normalizer,
            ech,
            origin,
            pairs,
            mirror,
            InterfaceConnector(
                settings.network.upstream_interface, settings.enforcement.destinations
            ),
            status_acquisition=StatusAcquisition(
                upstream,
                origin,
                InterfaceConnector(
                    settings.network.upstream_interface, settings.enforcement.destinations
                ),
            ),
        )
        intercept = Interception(boundary, connections)
        cleanup.push_async_callback(intercept.close)
        await intercept.start()
        health = EnforcementHealth(
            policies, state, root, signer, helper, dns, intercept, ech, crls, crl_service
        )
        cleanup.push_async_callback(policies.close)
        async with asyncio.timeout(settings.pair.health_timeout_seconds):
            if not await health.healthy():
                raise RuntimeError("local enforcement startup check failed")
        app = create_app(
            settings.pair,
            policies,
            health,
            await verifier(settings),
            EgressDNSAnchor(
                settings.pair.project_id,
                settings.pair.sandbox_id,
                root.fingerprint,
                str(root.dnskey),
            ),
        )
        config = uvicorn.Config(
            app,
            host=str(settings.network.control_address),
            port=settings.network.control_port,
            ssl_certfile=str(control_cert),
            ssl_keyfile=str(control_key),
            access_log=False,
            timeout_graceful_shutdown=5,
            limit_concurrency=64,
            backlog=64,
            server_header=False,
            proxy_headers=False,
        )
        config.load()
        config.ssl = control_tls
        server = uvicorn.Server(config)
        try:
            await server.serve()
            if not server.started:
                raise RuntimeError("HTTPS control listener did not start")
        finally:
            # No admissions while listeners and tasks are being drained.
            await policies.close()


def main() -> None:
    settings = load_settings()
    if os.getuid() != 0:
        raise RuntimeError("isolated egress guest root required")
    # Secrets are already parsed into private in-memory objects; do not expose
    # them to the supervised NGINX child or retain redundant environment copies.
    for name in ("WRAPPING_KEY_B64", "TLS_CERT_PEM", "TLS_KEY_PEM"):
        os.environ.pop(PREFIX + name, None)
    stage = "runtime-directory"
    try:
        with ExitStack() as cleanup:
            parent = Path("/run/ads-egress")
            info = parent.lstat()
            if parent.is_symlink() or not parent.is_dir() or info.st_uid != 0:
                raise RuntimeError("owned private runtime mount required")
            os.chmod(parent, 0o700)
            directory = Path(
                cleanup.enter_context(tempfile.TemporaryDirectory(prefix="run-", dir=parent))
            )
            stage = "control-tls"
            cert, key, context = tls_files(settings, directory)
            stage = "native-tls"
            library = TLSLibrary(Path("/opt/ads-openssl/lib"))
            stage = "kernel-boundary"
            boundary = KernelBoundary(settings.network)
            boundary.establish()
            stage = "block-custody"
            custody = cleanup.enter_context(mounted_custody(settings.devices, directory))
            stage = "serve"
            asyncio.run(serve(settings, custody, directory, library, boundary, cert, key, context))
    except Exception:
        # Only a code-owned constant: never exception text, inputs or tracebacks.
        print(f"egress runtime stage failed: {stage}", file=sys.stderr)
        raise
