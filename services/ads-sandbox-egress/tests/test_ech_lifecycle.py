import asyncio
import base64
import copy
import os
import time

import dns.message
import dns.rrset
import pytest

from ads_sandbox_egress.ech_lifecycle import ECHLifecycle
from ads_sandbox_egress.identity_store import StateUnavailable
from ads_sandbox_egress.tls import ECHKey, TLSFailure
from ads_sandbox_egress.tls_transport import FrontendIdentity, TLSStream
from test_identity_store import custody as custody
from test_identity_store import open_store
from test_tls import anyio_backend as anyio_backend
from test_tls import identity as identity
from test_tls import native as native


def owner(store, library, *, now=None, initialize=False, **kwargs):
    return ECHLifecycle(
        store,
        library,
        public_name=kwargs.get("public_name", "cover.example"),
        handshake_window=10,
        now=time.time() if now is None else now,
        initialize=initialize,
    )


def service_record(ttl=60):
    return dns.rrset.from_text(
        "secret.example.",
        ttl,
        "IN",
        "HTTPS",
        '1 target.example. mandatory=ech,alpn alpn="h2,http/1.1" '
        'port=8443 ipv4hint=1.1.1.1 ech=AAE= key65400="opaque"',
    )


@pytest.mark.parametrize("exhausted", [False, True])
def test_configuration_id_collision_is_bounded_before_durable_publication(
    native, custody, monkeypatch, exhausted
):
    store = open_store(custody, create=True)
    library = native[0]
    life = owner(store, library, initialize=True)
    original = life.configuration
    old = ECHKey.recover(store, life._current)
    real = library.generate_ech
    calls = []

    def generate(name):
        calls.append(1)
        return old if exhausted or len(calls) == 1 else real(name)

    monkeypatch.setattr(library, "generate_ech", generate)
    try:
        if exhausted:
            with pytest.raises(StateUnavailable, match="allocation"):
                life.rotate(now=time.time())
            assert calls == [1] * 16
            assert life.configuration == original
            assert len(store.key_names("ech")) == 1
        else:
            life.rotate(now=time.time())
            assert life.configuration[6] != original[6]
            assert 2 <= len(calls) <= 16
            assert len(store.key_names("ech")) == 2
    finally:
        life.close()
        store.close()


def test_rewrite_preserves_parameters_and_retained_identity(native, custody):
    library, _, _ = native
    now = time.time()
    store = open_store(custody, create=True)
    life = owner(store, library, now=now, initialize=True)
    original = service_record()
    before = copy.deepcopy(original)
    publication = life.rewrite(original, now=now)
    old = life.configuration
    assert original == before
    assert publication.records.ttl == 60
    assert publication.retain_until == now + 70
    assert publication.dependency
    for a, b in zip(original, publication.records, strict=True):
        assert a.priority == b.priority and a.target == b.target
        assert a.params.keys() == b.params.keys()
        assert b.params[5].ech == old
        assert all(a.params[k] == b.params[k] for k in a.params if k != 5)
    query = dns.message.make_query("secret.example.", "HTTPS")
    answer = dns.message.make_response(query)
    answer.answer.append(publication.records)
    store.commit_publication(
        "dns-generation/one",
        answer.to_wire(),
        (publication.dependency,),
        publication.retain_until,
    )
    life.close()
    store.close()
    store = open_store(custody)
    life = owner(store, library, now=now + 1)
    try:
        assert life.configuration == old
        assert life.rewrite(original, now=now + 1).dependency == publication.dependency
        assert (
            ECHKey.recover(store, publication.dependency).private_pem
            not in (custody[0] / "identity.sqlite").read_bytes()
        )
    finally:
        life.close()
        store.close()


@pytest.mark.parametrize("case", ["no-ech", "alias"])
def test_never_adds_ech_or_interprets_alias_parameters(native, custody, case):
    import dns.name
    import dns.rdtypes.svcbbase

    from ads_sandbox_egress.dns_wire import AliasService

    library, _, _ = native
    store = open_store(custody, create=True)
    life = owner(store, library, initialize=True)
    try:
        records = dns.rrset.from_text("secret.example.", 0, "IN", "HTTPS", "1 . alpn=h2")
        if case == "alias":
            records = dns.rrset.from_rdata(
                records.name,
                0,
                AliasService(
                    records.rdclass,
                    records.rdtype,
                    dns.name.from_text("target.example."),
                    {
                        dns.rdtypes.svcbbase.ParamKey.ECH: dns.rdtypes.svcbbase.GenericParam(
                            b"origin-opaque"
                        )
                    },
                ),
            )
        publication = life.rewrite(records, now=time.time())
        assert publication.dependency is None
        assert publication.records == records
        assert next(iter(publication.records)).to_wire() == next(iter(records)).to_wire()
    finally:
        life.close()
        store.close()


def test_publication_dependency_blocks_retirement_through_handshake_window(native, custody):
    library, _, _ = native
    now = time.time()
    store = open_store(custody, create=True)
    life = owner(store, library, now=now, initialize=True)
    first = life.rewrite(service_record(), now=now)
    store.commit_publication(
        "dns-generation/one",
        b"validated fixture generation",
        (first.dependency,),
        first.retain_until,
    )
    old_context = life.context
    in_flight = old_context.session()
    try:
        life.rotate(now=now + 1)
        assert life.configuration != ECHKey.recover(store, first.dependency).configuration
        with pytest.raises(TLSFailure, match="closed_tls_context"):
            old_context.session()
        assert not in_flight._closed
        life.collect(now=first.retain_until)
        assert ECHKey.recover(store, first.dependency)
        life.collect(now=first.retain_until + 1)
        with pytest.raises(StateUnavailable):
            store.key(first.dependency)
        # An already admitted handshake owns its OpenSSL context past key GC.
        assert not in_flight._closed
    finally:
        in_flight.close()
        life.close()
        store.close()


@pytest.mark.parametrize("failure", ["commit", "stage"])
def test_crash_points_never_publish_unretained_configuration(native, custody, monkeypatch, failure):
    library, _, _ = native
    now = time.time()
    store = open_store(custody, create=True)
    life = owner(store, library, now=now, initialize=True)
    before = life.configuration
    if failure == "commit":

        def failed(*args, **kwargs):
            raise StateUnavailable("injected commit failure")

        monkeypatch.setattr(store, "commit_publication", failed)
    else:
        advance = store.advance

        def failed(name, expected, target):
            if target == "active":
                raise StateUnavailable("injected stage failure")
            return advance(name, expected, target)

        monkeypatch.setattr(store, "advance", failed)
    with pytest.raises(StateUnavailable, match="injected"):
        life.rotate(now=now + 1)
    if failure == "commit":
        assert life.configuration == before
    life.close()
    store.close()
    store = open_store(custody)
    life = owner(store, library, now=now + 2)
    try:
        assert (life.configuration == before) is (failure == "commit")
        assert life.context.session().close() is None
    finally:
        life.close()
        store.close()


def test_missing_state_wrong_scope_and_backward_clock_never_regenerate(native, custody):
    library, _, _ = native
    store = open_store(custody, create=True)
    with pytest.raises(StateUnavailable, match="missing"):
        owner(store, library)
    now = time.time()
    life = owner(store, library, now=now, initialize=True)
    try:
        with pytest.raises(StateUnavailable, match="backwards"):
            life.rotate(now=now - 1)
        with pytest.raises(StateUnavailable, match="retained"):
            owner(store, library, initialize=True)
        with pytest.raises(StateUnavailable, match="mismatch"):
            owner(store, library, public_name="different.example")
    finally:
        life.close()
        store.close()


@pytest.mark.anyio
async def test_real_cached_ech_survives_rotation_replacement_then_expires(
    native, custody, identity
):
    library, directory, executable = native
    private_directory = custody[0] / "state"
    private_directory.mkdir(mode=0o700)
    custody = (private_directory, *custody[1:])
    store = open_store(custody, create=True)
    now = time.time()
    life = owner(store, library, now=now, initialize=True)
    publication = life.rewrite(service_record(1), now=now)
    old = life.configuration
    store.commit_publication(
        "dns-generation/one",
        b"validated fixture generation",
        (publication.dependency,),
        publication.retain_until,
    )
    life.rotate(now=now + 1)
    current = life.configuration
    life.close()
    store.close()
    store = open_store(custody)
    life = owner(store, library, now=now + 2)
    certificate, private, trust = identity
    seen, tasks = [], set()

    async def prepare(hello):
        if not hello.ech_accepted:
            raise TLSFailure("unknown_ech_configuration")
        assert hello.server_name == "secret.example"
        assert hello.protocols == (b"h2", b"http/1.1")
        return FrontendIdentity((certificate,), private, b"h2")

    async def accept(reader, writer):
        stream = None
        try:
            stream = await TLSStream.accept(reader, writer, life.context, prepare)
            payload = await stream.read()
            seen.append(payload)
            stream.write(b"inspected\n")
            await stream.drain()
        except TLSFailure:
            pass
        finally:
            if stream is not None:
                stream.close()
            writer.close()

    def connected(reader, writer):
        task = asyncio.create_task(accept(reader, writer))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    listener = await asyncio.start_server(connected, "127.0.0.1", 0)

    async def client(configuration, expected):
        process = await asyncio.create_subprocess_exec(
            str(executable),
            "s_client",
            "-quiet",
            "-connect",
            f"127.0.0.1:{listener.sockets[0].getsockname()[1]}",
            "-servername",
            "secret.example",
            "-verify_hostname",
            "secret.example",
            "-verify_return_error",
            "-CAfile",
            str(trust),
            "-alpn",
            "h2,http/1.1",
            "-ech_config_list",
            base64.b64encode(configuration).decode(),
            env=dict(os.environ, LD_LIBRARY_PATH=str(directory), OPENSSL_CONF="/dev/null"),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with asyncio.timeout(5):
                process.stdin.write(b"request\n")
                await process.stdin.drain()
                response = await process.stdout.readline()
                if response != (b"inspected\n" if expected else b""):
                    if process.returncode is None:
                        process.kill()
                    _, errors = await process.communicate()
                    pytest.fail(
                        f"ECH config ID={configuration[6]} old={old[6]} current={current[6]} "
                        f"client failed: {errors!r}"
                    )
                assert response == (b"inspected\n" if expected else b"")
        finally:
            if process.returncode is None:
                process.kill()
            await process.communicate()

    try:
        await client(old, True)
        await client(current, True)
        life.collect(now=now + 12)
        await client(old, False)
        await client(library.generate_ech("cover.example").configuration, False)
        await client(current, True)
        assert seen == [b"request\n"] * 3
    finally:
        listener.close()
        await listener.wait_closed()
        for task in tuple(tasks):
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        life.close()
        store.close()
