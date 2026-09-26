"""Configured child trust is a boundary, not an optional alternative path."""

import asyncio
import time

import dns.message
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.dnssec_validation import CryptoBudget
from ads_sandbox_egress.resolution import ResolutionJob
from test_dns_transport import transport
from test_dnssec_chain import CHILD, PARENT, ROOT, PublicDNS
from test_dnssec_validation import material
from test_resolution import resolver


@pytest.mark.parametrize("kind", ["positive", "unsigned"])
def test_parent_signer_cannot_jump_above_closest_configured_anchor(kind):
    fixture = PublicDNS()
    ds = fixture.data[CHILD, dns.rdatatype.DS][0]
    fixture.data[CHILD, dns.rdatatype.DS] = fixture.signed(ds, ROOT)
    no_ds = dns.rrset.from_text(CHILD, 60, "IN", "NSEC", "z. NS NSEC RRSIG")

    class View:
        async def answer(self, query, *, deadline):
            question = query.question[0]
            if kind == "unsigned" and (question.name, question.rdtype) == (CHILD, dns.rdatatype.DS):
                response = dns.message.make_response(query)
                response.authority.extend(fixture.signed(no_ds, ROOT))
                return response
            return await fixture.answer(query, deadline=deadline)

    async def run():
        server = transport(View())
        _, port = await server.start("127.0.0.1", 0)
        try:
            instance = resolver(upstream_port=port)
            # The ordinary root path really is cryptographically usable.
            baseline = await PositiveChains(instance, {ROOT: fixture.keys[ROOT]}).authenticate(
                CHILD, ResolutionJob(time.monotonic() + 5), budget=CryptoBudget()
            )
            assert baseline.state == ("secure" if kind == "positive" else "insecure")
            # A different locally pinned parent key must not be bypassed.
            anchors = {
                ROOT: fixture.keys[ROOT],
                PARENT: dns.rrset.from_rdata(PARENT, 60, material()[1]),
            }
            protected = await PositiveChains(instance, anchors).authenticate(
                CHILD, ResolutionJob(time.monotonic() + 5), budget=CryptoBudget()
            )
            assert protected.state == "indeterminate"
            assert protected.trusted_keys is None
        finally:
            await server.close()

    asyncio.run(run())
