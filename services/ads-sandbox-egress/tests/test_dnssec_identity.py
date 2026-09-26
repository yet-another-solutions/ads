import asyncio
import base64
import shutil
import time

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from ads_sandbox_egress.dnssec_identity import DNSSECIdentities, DNSSECUnrepresentable
from ads_sandbox_egress.identity_store import StateUnavailable
from test_dns_transport import transport
from test_identity_store import custody as custody
from test_identity_store import open_store


def upstream(algorithm=15, flags=257, protocol=3):
    if algorithm in (8, 10):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm == 13:
        private = ec.generate_private_key(ec.SECP256R1())
    elif algorithm == 14:
        private = ec.generate_private_key(ec.SECP384R1())
    elif algorithm == 15:
        private = ed25519.Ed25519PrivateKey.generate()
    elif algorithm == 16:
        private = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError("fixture algorithm")
    return dns.dnssec.make_dnskey(private.public_key(), algorithm, flags=flags, protocol=protocol)


def signed(identity, rrset, now):
    return (
        rrset,
        dns.rrset.from_rdata(
            rrset.name, rrset.ttl, identity.sign(rrset, inception=now - 60, expiration=now + 600)
        ),
    )


@pytest.mark.parametrize("algorithm", [8, 10, 13, 14, 15, 16])
def test_mapping_preserves_algorithm_full_identity_and_verified_signatures(custody, algorithm):
    store = open_store(custody, create=True)
    try:
        identities = DNSSECIdentities(store)
        original = upstream(algorithm)
        mapped = identities.mapped(dns.name.from_text("example."), original)
        assert mapped.stage == "prepared" and mapped.dnskey != original
        assert (mapped.dnskey.algorithm, mapped.dnskey.flags, mapped.dnskey.protocol) == (
            original.algorithm,
            original.flags,
            original.protocol,
        )
        assert (
            mapped.fingerprint
            == identities.mapped(dns.name.from_text("EXAMPLE."), original).fingerprint
        )
        assert (
            mapped.fingerprint
            != identities.mapped(dns.name.from_text("other."), original).fingerprint
        )
        assert (
            mapped.fingerprint
            != identities.mapped(dns.name.from_text("example."), original, generation=2).fingerprint
        )
        records = dns.rrset.from_text("www.example.", 60, "IN", "A", "1.1.1.1")
        now = int(time.time())
        _, signatures = signed(mapped, records, now)
        dns.dnssec.validate(records, signatures, {mapped.zone: mapped.key_rrset(60)}, now=now)
        private = mapped.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        assert private not in (custody[0] / "identity.sqlite").read_bytes()
        assert private.hex() not in repr(mapped)
    finally:
        store.close()


def test_root_is_explicit_stable_and_required_on_recovery(custody):
    store = open_store(custody, create=True)
    identities = DNSSECIdentities(store)
    with pytest.raises(StateUnavailable, match="missing"):
        identities.root(expected_fingerprint="0" * 64)
    root = identities.initialize_root()
    with pytest.raises(StateUnavailable, match="exists"):
        identities.initialize_root()
    with pytest.raises(StateUnavailable, match="mismatched"):
        identities.root(expected_fingerprint="0" * 64)
    source = upstream()
    mapped = identities.mapped(dns.name.from_text("example."), source)
    store.close()
    recovered = open_store(custody)
    try:
        repository = DNSSECIdentities(recovered)
        assert repository.root(expected_fingerprint=root.fingerprint).dnskey == root.dnskey
        assert repository.mapped(mapped.zone, source).dnskey == mapped.dnskey
        assert repository.root(expected_fingerprint=root.fingerprint).stage == "prepared"
    finally:
        recovered.close()


def test_key_flags_and_protocol_are_not_silently_repaired(custody):
    store = open_store(custody, create=True)
    try:
        identities = DNSSECIdentities(store)
        original = upstream(flags=1, protocol=2)
        mapped = identities.mapped(dns.name.from_text("example."), original)
        assert mapped.dnskey.flags == 1 and mapped.dnskey.protocol == 2
        good = original.replace(flags=257, protocol=3)
        assert identities.mapped(mapped.zone, good).name != mapped.name
        unsupported = original.replace(algorithm=253)
        with pytest.raises(DNSSECUnrepresentable):
            identities.mapped(mapped.zone, unsupported)
    finally:
        store.close()


def test_same_short_key_tag_never_collapses_distinct_upstream_keys(custody, monkeypatch):
    store = open_store(custody, create=True)
    try:
        identities = DNSSECIdentities(store)
        first, second = upstream(), upstream()
        monkeypatch.setattr(dns.dnssec, "key_id", lambda key: 1234)
        assert dns.dnssec.key_id(first) == dns.dnssec.key_id(second)
        a = identities.mapped(dns.name.from_text("example."), first)
        b = identities.mapped(dns.name.from_text("example."), second)
        assert a.name != b.name and a.dnskey != b.dnskey
    finally:
        store.close()


def test_prepared_mapping_cannot_be_published_or_recreated_after_retirement(custody):
    store = open_store(custody, create=True)
    try:
        identities = DNSSECIdentities(store)
        original = upstream()
        key = identities.mapped(dns.name.from_text("example."), original)
        with pytest.raises(StateUnavailable, match="unpublished"):
            store.commit_publication("dnssec/test", b"candidate", (key.name,), 2000)
        store.advance(key.name, "prepared", "published")
        store.advance(key.name, "published", "active")
        store.commit_publication("dnssec/test", b"candidate", (key.name,), 2000)
        store.advance(key.name, "active", "retiring")
        with pytest.raises(StateUnavailable, match="live"):
            store.retire(key.name, now=1999)
        store.retire(key.name, now=2001)
        with pytest.raises(StateUnavailable, match="unavailable"):
            identities.mapped(key.zone, original)
        assert identities.mapped(key.zone, original, generation=2).name != key.name
    finally:
        store.close()


def test_scope_and_explicit_signature_bounds(custody):
    store = open_store(custody, create=True)
    try:
        key = DNSSECIdentities(store).mapped(dns.name.from_text("example."), upstream())
        records = dns.rrset.from_text("elsewhere.", 60, "IN", "A", "1.1.1.1")
        with pytest.raises(ValueError, match="scope"):
            key.sign(records, inception=100, expiration=200)
        records = dns.rrset.from_text("example.", 60, "IN", "A", "1.1.1.1")
        with pytest.raises(ValueError):
            key.sign(records, inception=200, expiration=100)
    finally:
        store.close()


@pytest.mark.parametrize("defect", [None, "expired", "invalid", "ds-mismatch"])
def test_independent_delv_validates_generated_chain_and_rejects_defects(custody, tmp_path, defect):
    if shutil.which("delv") is None:
        pytest.skip("independent BIND delv unavailable")
    store = open_store(custody, create=True)
    try:
        identities = DNSSECIdentities(store)
        root = identities.initialize_root()
        zone = identities.mapped(dns.name.from_text("example."), upstream())
        now = int(time.time())
        ds = dns.dnssec.make_ds(zone.zone, zone.dnskey, "SHA256")
        if defect == "ds-mismatch":
            ds = ds.replace(digest=bytes([ds.digest[0] ^ 1]) + ds.digest[1:])
        ds_set = dns.rrset.from_rdata(zone.zone, 60, ds)
        answer = dns.rrset.from_text("www.example.", 60, "IN", "A", "1.1.1.1")
        signature = zone.sign(
            answer, inception=now - 600, expiration=now - 1 if defect == "expired" else now + 600
        )
        if defect == "invalid":
            signature = signature.replace(
                signature=bytes([signature.signature[0] ^ 1]) + signature.signature[1:]
            )
        fixture = {
            (dns.name.root, dns.rdatatype.DNSKEY): signed(root, root.key_rrset(60), now),
            (zone.zone, dns.rdatatype.DS): signed(root, ds_set, now),
            (zone.zone, dns.rdatatype.DNSKEY): signed(zone, zone.key_rrset(60), now),
            (answer.name, answer.rdtype): (
                answer,
                dns.rrset.from_rdata(answer.name, 60, signature),
            ),
        }

        # Explicit EXTERNAL serving fixture: this proves generated crypto with
        # an independent validator, not the unimplemented synthetic-view owner.
        class View:
            async def answer(self, query, *, deadline):
                question = query.question[0]
                response = dns.message.make_response(query)
                response.flags |= dns.flags.RA
                response.flags &= ~dns.flags.AD  # Delv must validate independently.
                response.answer.extend(fixture[(question.name, question.rdtype)])
                return response

        anchor = tmp_path / "ads-dnssec-public.anchor"
        anchor.write_text(
            'trust-anchors { "." static-key 257 3 15 "'
            + base64.b64encode(root.dnskey.key).decode()
            + '"; };\n'
        )

        async def run():
            service = transport(View())
            host, port = await service.start("127.0.0.1", 0)
            process = None
            try:
                process = await asyncio.create_subprocess_exec(
                    "delv",
                    "@" + host,
                    "-p",
                    str(port),
                    "-a",
                    str(anchor),
                    "www.example.",
                    "A",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                output, error = await asyncio.wait_for(process.communicate(), 5)
                combined = output + error
                if defect is None:
                    assert b"fully validated" in combined, combined
                    assert b"1.1.1.1" in combined
                else:
                    assert b"fully validated" not in combined, combined
                    assert b"resolution failed" in combined, combined
            finally:
                if process is not None and process.returncode is None:
                    process.kill()
                    await process.communicate()
                await service.close()
            assert not service._tasks and service._accepted == 0

        asyncio.run(run())
    finally:
        store.close()
