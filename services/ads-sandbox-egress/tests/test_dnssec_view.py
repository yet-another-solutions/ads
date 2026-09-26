import asyncio
import copy
import runpy
import shutil
import time
from pathlib import Path
from uuid import uuid4

import dns.asyncquery
import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import msgspec
import pytest

from ads_commons.egress import EgressDNSAnchor
from ads_sandbox_egress.dnssec_answer import AnswerAuthentication
from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.dnssec_identity import DNSSECIdentities
from ads_sandbox_egress.dnssec_view import SyntheticDNS
from ads_sandbox_egress.ech_lifecycle import ECHLifecycle
from ads_sandbox_egress.policy import RequestDenied
from test_dns_transport import transport
from test_dnssec_chain import CHILD, HOST, ROOT, PublicDNS
from test_dnssec_validation import corrupt
from test_identity_store import custody as custody
from test_identity_store import open_store
from test_resolution import resolver
from test_tls import native as native


@pytest.fixture
def state(custody, native):
    store = open_store(custody, create=True)
    identities = DNSSECIdentities(store)
    root = identities.initialize_root()
    life = ECHLifecycle(
        store,
        native[0],
        public_name="cover.example",
        handshake_window=10,
        now=time.time(),
        initialize=True,
    )
    try:
        yield store, identities, root, life
    finally:
        life.close()
        store.close()


def make_view(state, fixture, port):
    store, identities, root, life = state
    return SyntheticDNS(
        AnswerAuthentication(
            PositiveChains(
                resolver(upstream_port=port),
                {ROOT: fixture.keys[ROOT]},
            )
        ),
        identities,
        root_fingerprint=root.fingerprint,
        ech=life,
        safe_udp_payload=1232,
    )


@pytest.mark.parametrize("case", ["good", "bad", "bad-cd", "expired", "root-bad", "private"])
def test_real_dns_pipeline_never_serves_raw_or_uncommitted_answer(state, case):
    fixture = PublicDNS()
    sig = next(iter(fixture.answer_sigs))
    if case.startswith("bad"):
        sig = corrupt(sig)
    if case == "expired":
        sig = fixture.signed(fixture.a, CHILD)[1][0]
        sig = sig.replace(expiration=fixture.now - 1)
    fixture.data[HOST, dns.rdatatype.A] = (
        fixture.a,
        dns.rrset.from_rdata(HOST, 60, sig),
    )
    if case == "root-bad":
        keys, signatures = fixture.data[ROOT, dns.rdatatype.DNSKEY]
        fixture.data[ROOT, dns.rdatatype.DNSKEY] = (
            keys,
            dns.rrset.from_rdata(ROOT, 60, corrupt(signatures[0])),
        )
    if case == "private":
        fixture.data[HOST, dns.rdatatype.A] = (
            dns.rrset.from_text(HOST, 60, "IN", "A", "10.0.0.1"),
        )
    query = dns.message.make_query(HOST, "A", want_dnssec=True)
    if case == "bad-cd":
        query.flags |= dns.flags.CD

    async def run():
        upstream = transport(fixture)
        _, port = await upstream.start("127.0.0.1", 0)
        try:
            view = make_view(state, fixture, port)
            if case == "private":
                with pytest.raises(RequestDenied):
                    await view.answer(query, deadline=time.monotonic() + 10)
                assert state[0].publication_head("dns-generation/") is None
                return
            result = await view.answer(query, deadline=time.monotonic() + 10)
            assert result.rcode() == (
                dns.rcode.NOERROR if case in ("good", "bad-cd") else dns.rcode.SERVFAIL
            )
            assert bool(result.flags & dns.flags.AD) is (case == "good")
            committed = state[0].publication_head("dns-generation/")
            assert bool(committed) is (case != "root-bad")
            if result.answer:
                assert result.answer[0] == fixture.a
                assert result.answer[1] != fixture.answer_sigs
            if case == "root-bad":
                assert any(int(option.code) == 0 for option in result.options)
        finally:
            await upstream.close()

    asyncio.run(run())


def test_ech_only_replacement_is_signed_checked_and_retained(state):
    fixture = PublicDNS()
    records = dns.rrset.from_text(
        HOST,
        60,
        "IN",
        "HTTPS",
        "1 . mandatory=ech,alpn alpn=h2 port=8443 ech=AAE= ipv4hint=1.1.1.1",
    )
    fixture.data[HOST, dns.rdatatype.HTTPS] = fixture.signed(records, CHILD)
    fixture.data[HOST, dns.rdatatype.A] = fixture.signed(fixture.a, CHILD)
    original = copy.deepcopy(records)
    query = dns.message.make_query(HOST, "HTTPS", want_dnssec=True)

    async def run():
        upstream = transport(fixture)
        _, port = await upstream.start("127.0.0.1", 0)
        try:
            view = make_view(state, fixture, port)
            answer = await view.answer(query, deadline=time.monotonic() + 10)
            assert answer.rcode() == dns.rcode.NOERROR and answer.flags & dns.flags.AD
            assert records == original
            result = answer.answer[0][0]
            assert result.params[5].ech == state[3].configuration
            assert result.target == records[0].target
            restored = result.replace(params={**result.params, 5: records[0].params[5]})
            assert restored.to_wire() == records[0].to_wire()
            assert state[0].dependency_horizon(state[3]._current) > time.time() + 60
        finally:
            await upstream.close()

    asyncio.run(run())


@pytest.mark.parametrize("failure", ["quota", "commit"])
def test_no_dns_response_can_escape_failed_durable_publication(state, monkeypatch, failure):
    from ads_sandbox_egress.identity_store import StateUnavailable

    fixture = PublicDNS()
    fixture.data[HOST, dns.rdatatype.A] = (fixture.a, fixture.answer_sigs)
    if failure == "quota":
        # Exhaust actual persistent capacity without evicting existing state.
        for number in range(7):
            state[0].commit_publication(
                f"occupied/{number}", b"x" * 120000, (state[3]._current,), time.time() + 1000
            )
        monkeypatch.setattr(
            state[0], "capacity", (state[0].directory / "identity.sqlite").stat().st_size
        )
    else:

        def fail(*args, **kwargs):
            raise StateUnavailable("injected publication failure")

        monkeypatch.setattr(state[0], "commit_publication", fail)

    async def run():
        upstream = transport(fixture)
        _, port = await upstream.start("127.0.0.1", 0)
        try:
            view = make_view(state, fixture, port)
            with pytest.raises(RequestDenied, match="persistent"):
                await view.answer(
                    dns.message.make_query(HOST, "A", want_dnssec=True),
                    deadline=time.monotonic() + 10,
                )
        finally:
            await upstream.close()

    asyncio.run(run())


def test_independent_delv_follows_stable_root_and_synthetic_delegations(state, tmp_path):
    if shutil.which("delv") is None:
        pytest.skip("independent BIND delv unavailable")
    fixture = PublicDNS()
    fixture.data[HOST, dns.rdatatype.A] = (fixture.a, fixture.answer_sigs)
    key = state[2].dnskey
    anchor = tmp_path / "sandbox-anchor.conf"
    installer = runpy.run_path(
        str(Path(__file__).parents[2] / "ads-sandbox-base/scripts/ads-install-dnssec-anchor")
    )["install"]
    assert (
        installer(
            msgspec.json.encode(EgressDNSAnchor(uuid4(), uuid4(), state[2].fingerprint, str(key))),
            anchor,
            tmp_path / "delv",
        )
        == state[2].fingerprint
    )

    async def run():
        upstream = transport(fixture)
        _, port = await upstream.start("127.0.0.1", 0)
        view = make_view(state, fixture, port)
        frontend = transport(view)
        _, client_port = await frontend.start("127.0.0.1", 0)
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                str(tmp_path / "delv"),
                "@127.0.0.1",
                "-p",
                str(client_port),
                HOST.to_text(),
                "A",
                "+root=.",
                "+rtrace",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            async with asyncio.timeout(10):
                output, errors = await process.communicate()
            assert process.returncode == 0, (output, errors)
            assert b"fully validated" in output, (output, errors)
            assert b"1.1.1.1" in output
            assert state[0].publication_head("dns-generation/") is not None
            # A second independent lookup must obtain fresh upstream evidence.
            count = len(fixture.calls)
            query = dns.message.make_query(HOST, "A", want_dnssec=True)
            response = await dns.asyncquery.udp(query, "127.0.0.1", port=client_port, timeout=5)
            assert response.flags & dns.flags.AD and len(fixture.calls) > count
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.communicate()
            await frontend.close()
            await upstream.close()

    asyncio.run(run())
