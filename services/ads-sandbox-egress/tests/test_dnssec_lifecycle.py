import asyncio
import json
import time

import dns.dnssec
import dns.flags
import dns.message
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.dnssec_identity import DNSSECIdentities
from ads_sandbox_egress.dnssec_lifecycle import DNSSECLifecycle
from ads_sandbox_egress.identity_store import StateUnavailable
from test_dns_transport import transport
from test_dnssec_chain import CHILD, HOST, PARENT, PublicDNS
from test_dnssec_identity import upstream
from test_dnssec_validation import corrupt, material
from test_dnssec_view import make_view
from test_dnssec_view import state as state
from test_identity_store import custody as custody
from test_identity_store import open_store
from test_tls import native as native


def publish(store, identity, until):
    if store.key_stage(identity.name) == "prepared":
        store.advance(identity.name, "prepared", "published")
    store.commit_publication(
        f"fixture/{until}/{identity.name}", b"fixture", (identity.name,), until
    )
    if store.key_stage(identity.name) == "published":
        store.advance(identity.name, "published", "active")


def test_durable_overlap_uses_pretransition_horizon_then_dependencies(custody):
    store = open_store(custody, create=True)
    try:
        identities = DNSSECIdentities(store)
        life = DNSSECLifecycle(identities)
        old_original, new_original = upstream(), upstream()
        old = identities.observed(CHILD, old_original)
        new = identities.observed(CHILD, new_original)
        publish(store, old, 200)
        life.commit(life.plan(CHILD, (old,), now=100))
        publish(store, new, 300)
        transition = life.plan(CHILD, (new,), now=150)
        assert len(transition.overlap) == 1
        assert transition.overlap[0].name == old.name
        assert transition.overlap[0].fingerprint == identities.recover(old.name).fingerprint
        life.commit(transition)
        publish(store, old, 400)  # response during overlap has both signatures
        resumed = DNSSECLifecycle(DNSSECIdentities(store))
        plan = resumed.plan(CHILD, (new,), now=201)
        assert not plan.overlap  # no perpetual extension by live traffic
        assert plan.retiring[old.name] == 200
        resumed.commit(plan)
        assert store.key_stage(old.name) == "retiring"
        with pytest.raises(StateUnavailable, match="live"):
            store.retire(old.name, now=399)
        resumed.commit(resumed.plan(CHILD, (new,), now=401))
        assert store.key_stage(old.name) == "retired"
        recovered = identities.observed(CHILD, old_original)
        assert recovered.name.endswith("/2")
        assert recovered.dnskey != old.dnskey
        assert store.key_stage(old.name) == "retired"
    finally:
        store.close()


def test_clock_rollback_and_stale_plan_refuse_publication(custody):
    store = open_store(custody, create=True)
    try:
        ids = DNSSECIdentities(store)
        life = DNSSECLifecycle(ids)
        key = ids.observed(CHILD, upstream())
        publish(store, key, 200)
        plan = life.plan(CHILD, (key,), now=100)
        life.commit(plan)
        with pytest.raises(StateUnavailable, match="changed"):
            life.commit(plan)
        with pytest.raises(StateUnavailable, match="journal"):
            life.plan(CHILD, (key,), now=99)
    finally:
        store.close()


@pytest.mark.parametrize("defect", [False, True])
def test_wire_rollover_cached_old_ds_keys_and_answer_are_compatible(state, defect):
    fixture = PublicDNS()
    fixture.data[HOST, dns.rdatatype.A] = (fixture.a, fixture.answer_sigs)

    async def run():
        server = transport(fixture)
        _, port = await server.start("127.0.0.1", 0)
        view = make_view(state, fixture, port)

        async def answer(owner, kind):
            query = dns.message.make_query(owner, kind, want_dnssec=True)
            query.flags |= dns.flags.CD
            return await view.answer(query, deadline=time.monotonic() + 10)

        try:
            old_answer = await answer(HOST, "A")
            old_keys = await answer(CHILD, "DNSKEY")
            old_ds = await answer(CHILD, "DS")
            private, key = material(flags=257)
            fixture.private[CHILD] = private
            fixture.keys[CHILD] = dns.rrset.from_rdata(CHILD, 60, key)
            fixture.data[CHILD, dns.rdatatype.DNSKEY] = fixture.signed(fixture.keys[CHILD], CHILD)
            ds = dns.dnssec.make_ds(CHILD, key, 2)
            fixture.data[CHILD, dns.rdatatype.DS] = fixture.signed(
                dns.rrset.from_rdata(CHILD, 60, ds), PARENT
            )
            fixture.data[HOST, dns.rdatatype.A] = fixture.signed(fixture.a, CHILD)
            if defect:
                records, sigs = fixture.data[HOST, dns.rdatatype.A]
                fixture.data[HOST, dns.rdatatype.A] = (
                    records,
                    dns.rrset.from_rdata(HOST, 60, corrupt(sigs[0])),
                )
            new_answer = await answer(HOST, "A")
            if defect:
                assert not new_answer.flags & dns.flags.AD
                assert len(new_answer.answer[1]) == 1
                with pytest.raises(dns.dnssec.ValidationFailure):
                    dns.dnssec.validate(
                        new_answer.answer[0],
                        new_answer.answer[1],
                        {CHILD: old_keys.answer[0]},
                    )
                return
            assert new_answer.flags & dns.flags.AD
            new_keys = await answer(CHILD, "DNSKEY")
            new_ds = await answer(CHILD, "DS")
            assert len(new_keys.answer[0]) == 2
            assert len(new_ds.answer[0]) == 2
            for records, signatures, keys in (
                (*old_answer.answer[:2], new_keys.answer[0]),
                (*new_answer.answer[:2], old_keys.answer[0]),
                (*new_keys.answer[:2], old_keys.answer[0]),
            ):
                dns.dnssec.validate(records, signatures, {CHILD: keys})
            # Old DS authenticates the overlap DNSKEY, and fresh DS still
            # offers the old cached DNSKEY path until its frozen expiry.
            old_key = old_keys.answer[0][0]
            old_digest = dns.dnssec.make_ds(CHILD, old_key, 2)
            assert old_digest in old_ds.answer[0] and old_digest in new_ds.answer[0]
            # The journal is durable public state, not a source of upstream data.
            names = state[0].key_names("dnssec")
            assert any(state[0].key_stage(name) == "retiring" for name in names)
            before = len(fixture.calls)
            await answer(HOST, "A")
            assert len(fixture.calls) > before
            head = state[0].publication_head("dns-generation/")
            assert isinstance(json.loads(head[1])["evidence"], list)
        finally:
            await server.close()

    asyncio.run(run())
