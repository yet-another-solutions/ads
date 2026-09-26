import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from ads_sandbox_egress.origin_tls import OriginContext, inspect_origin
from ads_sandbox_egress.tls import TLSContext, TLSFailure
from ads_sandbox_egress.tls_status import acquire_staples, install_staples
from ads_sandbox_egress.tls_transport import FrontendIdentity, TLSStream
from test_certificates import pair_signer as pair_signer
from test_tls import anyio_backend as anyio_backend
from test_tls import native as native


def response():
    return ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.TRY_LATER
    ).public_bytes(Encoding.DER)


@pytest.mark.parametrize("values", [(), (None,), (None, response()), (response(), None)])
def test_native_status_stack_preserves_missing_positions(native, values):
    library, _, _ = native
    context = TLSContext(library, (library.generate_ech("cover.example"),))
    session = context.session()
    try:
        install_staples(library, session._ssl, values)
        assert acquire_staples(library, session._ssl) == values
    finally:
        session.close()
        context.close()


@pytest.mark.parametrize("values", [(b"",), (b"bad",), (response() + b"extra",), (None,) * 17])
def test_native_status_rejects_malformed_and_oversized_input(native, values):
    library, _, _ = native
    context = TLSContext(library, (library.generate_ech("cover.example"),))
    session = context.session()
    try:
        with pytest.raises(TLSFailure):
            install_staples(library, session._ssl, values)
        assert acquire_staples(library, session._ssl) == ()
    finally:
        session.close()
        context.close()


@pytest.mark.anyio
@pytest.mark.parametrize("version", [0x0303, 0x0304])
@pytest.mark.parametrize("present", [False, True])
async def test_real_tls_status_acquisition_preserves_response_without_declaring_good(
    native, pair_signer, version, present
):
    library, _, _ = native
    certificate = pair_signer.certificate.public_bytes(Encoding.PEM)
    front = TLSContext(library, (library.generate_ech("cover.example"),))
    origin = OriginContext(library, extra_trust=(certificate,), system_trust=False)
    library.require(
        library.ssl.SSL_CTX_ctrl(origin._context, 124, version, library.ffi.NULL), "test_version"
    )
    tasks, streams = set(), []
    ready = asyncio.Event()
    stop = asyncio.Event()
    errors = []
    cert, key = pair_signer.certificate, pair_signer.private_key
    now = datetime.now(UTC)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "secret.example")])
        )
        .issuer_name(cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("secret.example")]), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(cert.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    revoked = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            leaf,
            cert,
            hashes.SHA256(),
            ocsp.OCSPCertStatus.REVOKED,
            now - timedelta(minutes=1),
            now + timedelta(minutes=5),
            now - timedelta(days=1),
            x509.ReasonFlags.key_compromise,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, cert)
        .sign(key, hashes.SHA256())
        .public_bytes(Encoding.DER)
    )
    staples = (revoked,) if present else ()

    async def prepare(hello):
        return replace(
            FrontendIdentity(
                (leaf.public_bytes(Encoding.PEM), certificate),
                leaf_key.private_bytes(
                    Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                ),
            ),
            staples=staples,
        )

    async def serve(r, w):
        stream = None
        try:
            stream = await TLSStream.accept(r, w, front, prepare)
            streams.append(stream)
            ready.set()
            await stop.wait()
        except Exception as exc:
            errors.append(exc)
        finally:
            if stream:
                stream.close()
            w.close()

    def spawn(r, w):
        task = asyncio.create_task(serve(r, w))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    listener = await asyncio.start_server(spawn, "127.0.0.1", 0)
    upstream = None
    try:
        r, w = await asyncio.open_connection(*listener.sockets[0].getsockname())
        upstream, observed = await inspect_origin(r, w, origin, "secret.example", ())
        await asyncio.wait_for(ready.wait(), 2)
        assert library.ssl.SSL_ctrl(streams[0].session._ssl, 127, 0, library.ffi.NULL) == 1
        assert acquire_staples(library, streams[0].session._ssl) == staples
        assert observed.staples == staples
        # Certificate-path verification is independent from the unsuccessful
        # stapled response. The status verifier must separately reject it.
        assert observed.verified, [(issue.code, issue.depth) for issue in observed.issues]
        if present:
            assert ocsp.load_der_ocsp_response(observed.staples[0]).certificate_status is (
                ocsp.OCSPCertStatus.REVOKED
            )
        assert not errors
    finally:
        stop.set()
        if upstream:
            upstream.close()
        listener.close()
        await asyncio.gather(*tuple(tasks), return_exceptions=True)
        await listener.wait_closed()
        front.close()
        origin.close()
    assert not front._sessions and not origin._sessions
