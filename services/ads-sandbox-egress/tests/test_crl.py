import asyncio
import ipaddress
import socket
import sqlite3
import ssl
import subprocess
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ads_sandbox_ca.certificates import mint
from ads_sandbox_egress.certificate_mirror import CertificateMirror
from ads_sandbox_egress.certificate_validation import CertificateValidator
from ads_sandbox_egress.certificates import (
    CertificateDefectRequiresMirror,
    CertificatePairs,
    EgressSigner,
    PairDestination,
    certificate_builder,
)
from ads_sandbox_egress.crl import CRLAuthority, CRLRepository, CRLUnavailable
from ads_sandbox_egress.crl_http import LocalCRLService
from ads_sandbox_egress.identity_store import IdentityStore, StateUnavailable
from ads_sandbox_egress.issuers import untrusted_issuer
from ads_sandbox_egress.origin_tls import OriginCertificate
from ads_sandbox_egress.tls import TLSContext
from test_certificates import observation
from test_certificates import pair_signer as pair_signer
from test_certificates import pair_state as pair_state
from test_minted_anchor import _hierarchy
from test_origin_tls import certificate_fixture
from test_tls import native as native

PEM = serialization.Encoding.PEM


@pytest.fixture
def anyio_backend():
    return "asyncio"


def authority(signer):
    return CRLAuthority(signer.certificate, signer.private_key)


def public_fixture_crl(issuer, key, revoked=None):
    now = datetime.now(UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(hours=1))
    )
    if revoked is not None:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoked.serial_number)
            .revocation_date(now - timedelta(seconds=30))
            .build()
        )
    return builder.sign(key, hashes.SHA384()).public_bytes(PEM)


@pytest.mark.parametrize("depth", [0, 1])
def test_leaf_and_intermediate_revocation_under_actual_minted_hierarchy(
    native, pair_state, tmp_path, depth
):
    library, _, _ = native
    root, parent, parent_key, root_key = _hierarchy()
    _, _, original_leaf, _ = certificate_fixture(tmp_path, "valid")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate_builder(original_leaf, leaf_key, parent, "http://origin.invalid/crl").sign(
        parent_key, hashes.SHA384()
    )
    findings = CertificateValidator(library, root.public_bytes(PEM)).observe(
        tuple(cert.public_bytes(PEM) for cert in (leaf, parent, root)),
        "origin.example",
        crls=(
            public_fixture_crl(parent, parent_key, leaf if depth == 0 else None),
            public_fixture_crl(root, root_key, parent if depth == 1 else None),
        ),
        check_revocation=True,
    )
    assert {(issue.code, issue.depth) for issue in findings} == {(23, depth)}
    source = OriginCertificate(
        (
            leaf.public_bytes(serialization.Encoding.DER),
            parent.public_bytes(serialization.Encoding.DER),
        ),
        tuple(cert.public_bytes(serialization.Encoding.DER) for cert in (leaf, parent, root)),
        findings,
        b"h2",
    )
    local_root, local_parent, local_parent_key, local_root_key = _hierarchy()
    material = mint(
        local_parent.public_bytes(PEM) + local_root.public_bytes(PEM),
        local_parent_key.private_bytes(
            PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )
    signer = EgressSigner.load(
        material.certificate,
        material.private_key,
        (local_parent.public_bytes(PEM), local_root.public_bytes(PEM)),
    )
    # These are PUBLIC fixture inputs from the configured hierarchy's issuers.
    # Production egress neither possesses nor manufactures their private keys.
    issuer_crls = (
        public_fixture_crl(local_parent, local_parent_key),
        public_fixture_crl(local_root, local_root_key),
    )
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    repository = CRLRepository(store)
    validator = CertificateValidator(library, material.certificate + material.chain)
    process = untrusted_issuer(signer.certificate.not_valid_after_utc)
    try:
        mirror = CertificateMirror(
            signer,
            process,
            validator,
            f"http://egress.invalid/crl/{signer.fingerprint}.der",
            crls=repository,
            issuer_crls=issuer_crls,
        )
        result = mirror.mirror(
            PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"), source
        )
        local_crls = tuple(
            repository.get(
                x509.load_pem_x509_certificate(cert).fingerprint(hashes.SHA256()).hex(),
                now=datetime.now(UTC),
            ).crl.public_bytes(PEM)
            for cert in result.certificate_chain[1:-2]
        )
        assert {
            (issue.code, issue.depth)
            for issue in validator.observe(
                result.certificate_chain,
                "origin.example",
                crls=local_crls + issuer_crls,
                check_revocation=True,
            )
        } == {(23, depth)}
        assert store.crl_head(local_parent.fingerprint(hashes.SHA256()).hex()) is None
        assert store.crl_head(local_root.fingerprint(hashes.SHA256()).hex()) is None
        missing = CertificateMirror(
            signer,
            process,
            validator,
            f"http://egress.invalid/crl/{signer.fingerprint}.der",
            crls=repository,
        )
        with pytest.raises(CertificateDefectRequiresMirror, match="outcome_mismatch"):
            missing.mirror(
                PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"), source
            )
    finally:
        store.close()
        (tmp_path / "private.pem").unlink()


def test_refresh_reuses_reclaimed_pages_without_forgetting_revocations(pair_signer, pair_state):
    store = IdentityStore(*pair_state, capacity=65536, create=True)
    repository = CRLRepository(store, lifetime_seconds=60)
    signer = authority(pair_signer)
    now = datetime.now(UTC).replace(microsecond=0)
    try:
        for generation in range(1, 41):
            result = repository.publish(signer, now=now + timedelta(seconds=61 * generation))
            assert result.number == generation
        assert (pair_state.directory / "identity.sqlite").stat().st_size <= 65536
        assert store._connection().execute("SELECT count(*) FROM publications").fetchone() == (1,)
        with pytest.raises(CRLUnavailable, match="authority_not_current"):
            repository.publish(signer, now=signer.certificate.not_valid_after_utc)
        with pytest.raises(ValueError, match="UTC"):
            repository.publish(signer, now=datetime.now())
    finally:
        store.close()


def test_durable_revocation_refresh_and_independent_native_validation(
    native, pair_signer, pair_state, tmp_path
):
    library, _, _ = native
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    signer = authority(pair_signer)
    now = datetime.now(UTC).replace(microsecond=0)
    try:
        repository = CRLRepository(store, lifetime_seconds=60)
        first = repository.publish(signer, now=now)
        assert first.number == 1 and len(first.crl) == 0
        assert repository.publish(signer, now=now + timedelta(seconds=1)).der == first.der
        pairs = CertificatePairs(
            store, pair_signer, f"http://egress.invalid/crl/{signer.identity}.der"
        )
        pair = pairs.valid(
            PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"),
            observation(tmp_path),
        )
        validator = CertificateValidator(library, pair_signer.certificate.public_bytes(PEM))
        assert (
            validator.observe(
                pair.certificate_chain,
                "origin.example",
                crls=(first.crl.public_bytes(PEM),),
                check_revocation=True,
            )
            == ()
        )
        target = x509.load_pem_x509_certificate(pair.certificate_chain[0])
        second = repository.publish(signer, now=now, revoke=target)
        assert second.number == 2 and len(second.crl) == 1
        assert {
            issue.code
            for issue in validator.observe(
                pair.certificate_chain,
                "origin.example",
                crls=(second.crl.public_bytes(PEM),),
                check_revocation=True,
            )
        } == {23}
        assert repository.publish(signer, now=now, revoke=target).der == second.der
        store.close()
        store = IdentityStore(*pair_state, capacity=2**20)
        repository = CRLRepository(store, lifetime_seconds=60)
        assert repository.get(signer.identity, now=now).der == second.der
        refreshed = repository.publish(signer, now=now + timedelta(seconds=31))
        assert refreshed.number == 3
        assert refreshed.crl[0].serial_number == target.serial_number
        assert refreshed.crl[0].revocation_date_utc == second.crl[0].revocation_date_utc
        with pytest.raises(CRLUnavailable, match="clock_rollback"):
            repository.publish(signer, now=now)
        with pytest.raises(CRLUnavailable, match="not_current"):
            repository.get(signer.identity, now=now + timedelta(seconds=92))
        # Expired head is retained: subsequent refresh cannot reset its number
        # or lose previously revoked serials even after cleanup.
        store.prune_crls(signer.identity, now=(now + timedelta(seconds=100)).timestamp())
        assert store.crl_head(signer.identity)[0] == 3
        assert len(store._connection().execute("SELECT * FROM publications").fetchall()) == 1
        fresh = repository.publish(signer, now=now + timedelta(seconds=100))
        assert fresh.number == 4 and fresh.crl[0].serial_number == target.serial_number
    finally:
        store.close()
        (tmp_path / "private.pem").unlink()


def test_crl_state_tampering_and_generation_conflict_fail_closed(pair_state):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    identity = "a" * 64
    assert store.commit_crl(identity, 0, b"one", 100.0) == 1
    with pytest.raises(StateUnavailable, match="generation"):
        store.commit_crl(identity, 0, b"two", 200.0)
    with pytest.raises(ValueError):
        store.commit_publication("crl/" + identity + "/00000000000000000002", b"DNS", (), 200.0)
    with pytest.raises(ValueError):
        store.crl_head("../outside")
    store.close()
    with sqlite3.connect(pair_state.directory / "identity.sqlite") as database:
        database.execute("UPDATE publications SET content=?", (b"modified",))
    with pytest.raises(StateUnavailable, match="authentication"):
        IdentityStore(*pair_state, capacity=2**20)


def test_no_parent_keys_wrong_issuer_or_invalid_publication_adopted(
    pair_signer, pair_state, tmp_path
):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    repository = CRLRepository(store)
    signer = authority(pair_signer)
    now = datetime.now(UTC)
    try:
        original = observation(tmp_path)
        origin_leaf = x509.load_der_x509_certificate(original.presented_chain[0])
        with pytest.raises(ValueError, match="target"):
            repository.publish(signer, now=now, revoke=origin_leaf)
        assert store.crl_head(signer.identity) is None
        with pytest.raises(CRLUnavailable, match="unknown"):
            repository.get(signer.identity, now=now)
        store.commit_crl(signer.identity, 0, b'{"issuer":"invalid","der":""}', now.timestamp())
        with pytest.raises(StateUnavailable, match="authenticated"):
            repository.get(signer.identity, now=now)
    finally:
        store.close()
        (tmp_path / "private.pem").unlink()


async def start_service(repository, source="127.0.0.1", **kwargs):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    address = sock.getsockname()
    service = LocalCRLService(repository, ipaddress.ip_address(source), **kwargs)
    try:
        await service.start(sock)
    except BaseException:
        sock.close()
        raise
    return service, address


@pytest.mark.anyio
async def test_real_http_crl_get_head_and_bounded_private_exception(pair_signer, pair_state):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    repository = CRLRepository(store)
    published = repository.publish(authority(pair_signer), now=datetime.now(UTC))
    service, address = await start_service(repository)
    url = urlsplit(service.url(published.issuer))
    try:
        for method in ("GET", "HEAD"):
            reader, writer = await asyncio.open_connection(*address)
            try:
                writer.write(f"{method} {url.path} HTTP/1.1\r\nHost: {url.netloc}\r\n\r\n".encode())
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), 2)
                headers, body = response.split(b"\r\n\r\n", 1)
                assert headers.startswith(b"HTTP/1.1 200 ")
                assert b"application/pkix-crl" in headers
                assert body == (published.der if method == "GET" else b"")
            finally:
                writer.close()
                await writer.wait_closed()
        assert service.healthy
    finally:
        await service.close()
        store.close()
    assert not service.healthy and not service._tasks and not service._writers
    with pytest.raises(OSError):
        await asyncio.open_connection(*address)


@pytest.mark.anyio
@pytest.mark.parametrize("case", ["path", "host", "method", "body", "unknown", "source", "timeout"])
async def test_local_crl_denial_is_real_reset_without_http(pair_signer, pair_state, case):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    repository = CRLRepository(store)
    published = repository.publish(authority(pair_signer), now=datetime.now(UTC))
    service, address = await start_service(
        repository, source="127.0.0.2" if case == "source" else "127.0.0.1", deadline=0.1
    )
    url = urlsplit(service.url(published.issuer))
    path = (
        "/control"
        if case == "path"
        else "/crl/" + "0" * 64 + ".der"
        if case == "unknown"
        else url.path
    )
    host = "other.example" if case == "host" else url.netloc
    method = "POST" if case == "method" else "GET"
    body = "Content-Length: 1\r\n" if case == "body" else ""
    reader, writer = await asyncio.open_connection(*address)
    try:
        if case != "timeout":
            writer.write(f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n{body}\r\n".encode())
        with pytest.raises((ConnectionResetError, BrokenPipeError)):
            await writer.drain()
            await asyncio.wait_for(reader.read(), 2)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass
        await service.close()
        store.close()
    assert not service._tasks and not service._writers


async def assert_reset(reader, writer):
    try:
        with pytest.raises((ConnectionResetError, BrokenPipeError)):
            await writer.drain()
            await asyncio.wait_for(reader.read(), 2)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["state", "database", "stale"])
async def test_service_failure_has_no_response_and_only_internal_faults_latch(
    pair_signer, pair_state, monkeypatch, caplog, failure
):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    repository = CRLRepository(store)
    publication = repository.publish(authority(pair_signer), now=datetime.now(UTC))
    service, address = await start_service(repository)
    url = urlsplit(service.url(publication.issuer))

    def failed_get(*args, **kwargs):
        if failure == "state":
            raise StateUnavailable("fixture private detail must not be logged")
        if failure == "database":
            raise sqlite3.DatabaseError("fixture private detail must not be logged")
        raise CRLUnavailable("crl_not_current")

    monkeypatch.setattr(repository, "get", failed_get)
    try:
        reader, writer = await asyncio.open_connection(*address)
        writer.write(f"GET {url.path} HTTP/1.1\r\nHost: {url.netloc}\r\n\r\n".encode())
        await assert_reset(reader, writer)
        assert service.healthy == (failure == "stale")
        if failure != "stale":
            with pytest.raises(CRLUnavailable, match="listener"):
                service.url(publication.issuer)
            reader, writer = await asyncio.open_connection(*address)
            await assert_reset(reader, writer)
    finally:
        await service.close()
        store.close()
    assert not service._tasks and not service._writers
    assert "fixture private detail" not in caplog.text


@pytest.mark.anyio
async def test_capacity_and_shutdown_reset_live_clients_without_leaking_tasks(
    pair_signer, pair_state
):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    repository = CRLRepository(store)
    repository.publish(authority(pair_signer), now=datetime.now(UTC))
    service, address = await start_service(repository, maximum_connections=1)
    first_reader, first_writer = await asyncio.open_connection(*address)
    try:
        async with asyncio.timeout(2):
            while not service._tasks:
                await asyncio.sleep(0)
        second_reader, second_writer = await asyncio.open_connection(*address)
        await assert_reset(second_reader, second_writer)
        assert service.healthy and len(service._tasks) == 1
        await asyncio.wait_for(service.close(), 2)
        await assert_reset(first_reader, first_writer)
        assert not service._tasks and not service._writers
        with socket.socket() as sock, pytest.raises(RuntimeError):
            await service.start(sock)
    finally:
        first_writer.close()
        await service.close()
        store.close()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "extra",
    [
        "Transfer-Encoding: chunked\r\n",
        "Upgrade: websocket\r\n",
        "Expect: 100-continue\r\n",
        "Range: bytes=0-5\r\n",
        "HTTP2-Settings: AAAA\r\n",
        "Host: evil.invalid\r\n",
        "X-Filler: " + "x" * 4096 + "\r\n",
        "".join(f"X-{index}: a\r\n" for index in range(33)),
    ],
)
async def test_private_crl_route_cannot_be_reused_as_general_http(pair_signer, pair_state, extra):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    repository = CRLRepository(store)
    publication = repository.publish(authority(pair_signer), now=datetime.now(UTC))
    service, address = await start_service(repository)
    url = urlsplit(service.url(publication.issuer))
    try:
        reader, writer = await asyncio.open_connection(*address)
        writer.write(f"GET {url.path} HTTP/1.1\r\nHost: {url.netloc}\r\n{extra}\r\n".encode())
        await assert_reset(reader, writer)
        assert service.healthy
    finally:
        await service.close()
        store.close()


@pytest.mark.anyio
@pytest.mark.parametrize("additional", ["none", "expired", "hostname"])
async def test_mirrored_revocation_is_durable_fetchable_and_rejected_by_tls_client(
    native, pair_signer, pair_state, tmp_path, additional
):
    library, _, _ = native
    _, origin_ca, original_leaf, origin_crl = certificate_fixture(tmp_path, additional)
    name = "wrong.example" if additional == "hostname" else "origin.example"
    origin_chain = (original_leaf.public_bytes(PEM), origin_ca)
    findings = CertificateValidator(library, origin_ca).observe(
        origin_chain, name, crls=(origin_crl,), check_revocation=True
    )
    expected = {23} | (
        {10} if additional == "expired" else {62} if additional == "hostname" else set()
    )
    assert {issue.code for issue in findings} == expected
    original = OriginCertificate(
        (original_leaf.public_bytes(serialization.Encoding.DER),),
        tuple(
            x509.load_pem_x509_certificate(cert).public_bytes(serialization.Encoding.DER)
            for cert in origin_chain
        ),
        findings,
        b"h2",
    )
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    repository = CRLRepository(store)
    service, address = await start_service(repository)
    trust_pem = pair_signer.certificate.public_bytes(PEM)
    validator = CertificateValidator(library, trust_pem)
    mirror = CertificateMirror(
        pair_signer,
        untrusted_issuer(pair_signer.certificate.not_valid_after_utc),
        validator,
        service.url(pair_signer.fingerprint),
        crls=repository,
    )
    try:
        replacement = mirror.mirror(
            PairDestination(ipaddress.ip_address("1.1.1.1"), 443, name), original
        )
        leaf = x509.load_pem_x509_certificate(replacement.certificate_chain[0])
        distribution = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        assert distribution[0].full_name[0].value == service.url(pair_signer.fingerprint)
        # Publication was committed before mirror returned; real HTTP fetch
        # carries exactly that signed generation, with no private material.
        url = urlsplit(service.url(pair_signer.fingerprint))
        reader, writer = await asyncio.open_connection(*address)
        try:
            writer.write(f"GET {url.path} HTTP/1.1\r\nHost: {url.netloc}\r\n\r\n".encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 2)
        finally:
            writer.close()
            await writer.wait_closed()
        crl = x509.load_der_x509_crl(response.split(b"\r\n\r\n", 1)[1])
        assert crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None
        assert {
            issue.code
            for issue in validator.observe(
                replacement.certificate_chain,
                name,
                crls=(crl.public_bytes(PEM),),
                check_revocation=True,
            )
        } == expected
        (tmp_path / "client-trust.pem").write_bytes(trust_pem + crl.public_bytes(PEM))
        (tmp_path / "substitute.pem").write_bytes(replacement.certificate_chain[0])
        result = subprocess.run(
            [
                "openssl",
                "verify",
                "-crl_check_all",
                "-CAfile",
                str(tmp_path / "client-trust.pem"),
                str(tmp_path / "substitute.pem"),
            ],
            capture_output=True,
            timeout=5,
        )
        assert result.returncode != 0 and b"error 23 " in result.stderr
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.load_verify_locations(cafile=tmp_path / "client-trust.pem")
        client_context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
        client_context.set_alpn_protocols(["h2"])
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_context.wrap_bio(incoming, outgoing, server_hostname=name)
        context = TLSContext(library, (library.generate_ech("cover.example"),))
        server = context.session()
        rejected = False
        try:
            for _ in range(30):
                try:
                    client.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLCertVerificationError as error:
                    assert error.verify_code in expected
                    rejected = True
                    break
                if data := outgoing.read():
                    server.feed(data)
                if server.handshake() == "hello":
                    server.resume(replacement.certificate_chain, replacement.private_key, b"h2")
                    server.handshake()
                if data := server.drain():
                    incoming.write(data)
            assert rejected and not server.established
        finally:
            server.close()
            context.close()
        assert not context._sessions
    finally:
        await service.close()
        store.close()
        (tmp_path / "private.pem").unlink()
