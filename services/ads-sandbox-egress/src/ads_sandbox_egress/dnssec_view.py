"""Fresh synthetic DNS view: inspect, transform, check, commit, then render.

The persistent store holds identities and publication dependencies, not a
resolver cache. Each call reacquires upstream data under the original job
deadline. The candidate verifier can access only the acquired transformed
evidence, and uses only the independently installed sandbox root.
"""

from __future__ import annotations

import copy
import json
import logging
import time
from uuid import uuid4

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.RRSIG
import dns.rrset

from ads_sandbox_egress.dnssec_answer import AnswerAuthentication, MessageAuthentication
from ads_sandbox_egress.dnssec_chain import PositiveChains, exact
from ads_sandbox_egress.dnssec_identity import (
    DNSSECIdentities,
    DNSSECUnrepresentable,
)
from ads_sandbox_egress.dnssec_lifecycle import DNSSECLifecycle, ZonePlan
from ads_sandbox_egress.dnssec_response import diagnostics, fallback, render, resolution_failure
from ads_sandbox_egress.dnssec_transform import DNSSECTransformer, KeySubstitution
from ads_sandbox_egress.dnssec_validation import CryptoBudget
from ads_sandbox_egress.ech_lifecycle import ECHLifecycle
from ads_sandbox_egress.identity_store import StateUnavailable
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import ResolutionJob, UpstreamResolver
from ads_sandbox_egress.resolution_answer import assemble

QueryKey = tuple[dns.name.Name, dns.rdatatype.RdataType]


def _query(message: dns.message.Message) -> QueryKey:
    if len(message.question) != 1:
        raise DNSSECUnrepresentable("candidate evidence question")
    question = message.question[0]
    return question.name, question.rdtype


class _CandidateEvidence(UpstreamResolver):
    """Bounded read-only verifier input, never a fallback upstream resolver."""

    def __init__(
        self, original: UpstreamResolver, messages: dict[QueryKey, dns.message.Message]
    ) -> None:
        super().__init__(original.boundary, original.limits, upstream_port=original.upstream_port)
        self._messages = messages

    async def exchange(
        self, name: dns.name.Name, rdtype: dns.rdatatype.RdataType, job: ResolutionJob
    ) -> dns.message.Message:
        if time.monotonic() >= job.deadline:
            raise RequestDenied("dns_resolution_deadline")
        found = self._messages.get((name, rdtype))
        if found is None:
            raise DNSSECUnrepresentable("candidate requires unacquired evidence")
        self.inspect(found)
        return copy.deepcopy(found)


class SyntheticDNS:
    def __init__(
        self,
        authentication: AnswerAuthentication,
        identities: DNSSECIdentities,
        *,
        root_fingerprint: str,
        ech: ECHLifecycle,
        safe_udp_payload: int,
    ) -> None:
        if not 512 <= safe_udp_payload <= 1232:
            raise ValueError("explicit safe DNS payload required")
        self.authentication, self.identities = authentication, identities
        self.resolver = authentication.chains.resolver
        self.store, self.ech = identities.store, ech
        self.lifecycle = DNSSECLifecycle(identities)
        self.root = identities.root(expected_fingerprint=root_fingerprint)
        self.safe_udp_payload = safe_udp_payload
        if authentication.chains.closest_anchor(dns.name.root) != dns.name.root:
            raise ValueError("synthetic root requires independently configured upstream root")

    async def answer(self, query: dns.message.Message, *, deadline: float) -> dns.message.Message:
        if len(query.question) != 1:
            raise RequestDenied("dns_question_count")
        question = query.question[0]
        job = ResolutionJob(deadline)
        budget = CryptoBudget()
        authentication = MessageAuthentication("indeterminate", (), ())
        try:
            acquired = await self.resolver.acquire(
                question.name.to_text(), question.rdtype, job=job
            )
            original = assemble(acquired, deadline=deadline)
            authentication = await self.authentication.classify(original, job, budget=budget)
            if authentication.resolution_failure:
                return resolution_failure(query, original, safe_udp_payload=self.safe_udp_payload)
            if authentication.state == "indeterminate":
                raise DNSSECUnrepresentable("upstream authentication indeterminate")
            root = await self.authentication.chains.authenticate(dns.name.root, job, budget=budget)
            if root.state != "secure" or root.trusted_keys is None:
                # Adding the stable anchor must not repair an upstream root
                # failure. Such a root cannot support this bridge construction.
                raise DNSSECUnrepresentable("upstream root cannot support stable bridge")
            messages = [
                *acquired.messages,
                *authentication.discovery_messages,
                *(message for zone in authentication.zones for message in zone.messages),
                *root.messages,
            ]
            # A direct DS query authenticates the parent RRset without needing
            # child keys. Substitution additionally needs that exact child
            # DNSKEY evidence; obtain it under the same original budget.
            known_keys = {
                message.question[0].name
                for message in messages
                if message.question[0].rdtype == dns.rdatatype.DNSKEY
            }
            child_names = {
                rrset.name
                for message in messages
                for rrset in (*message.answer, *message.authority)
                if rrset.rdtype == dns.rdatatype.DS
            }
            for child in sorted(child_names - known_keys):
                messages.append(await self.resolver.exchange(child, dns.rdatatype.DNSKEY, job))
            transformed, candidate, dependencies, horizon, plans = self._construct(
                messages,
                original,
                root.trusted_keys,
                job,
                budget,
                overlap=authentication.state == "secure",
            )
            checker = AnswerAuthentication(
                PositiveChains(
                    _CandidateEvidence(self.resolver, transformed),
                    {dns.name.root: self.root.key_rrset(root.trusted_keys.ttl)},
                )
            )
            checked = await checker.classify(candidate, job, budget=budget)
            if checked.state != authentication.state or {
                int(item.code) for item in diagnostics(checked)
            } != {int(item.code) for item in diagnostics(authentication)}:
                raise DNSSECUnrepresentable("synthetic authentication outcome changed")
            if time.monotonic() >= deadline:
                raise RequestDenied("dns_resolution_deadline")
            # Keys are prepared while constructing. Staging is durable before
            # this transaction; a crash may leave unused keys, never a served
            # answer depending on a key that was not persisted.
            for name in dependencies:
                if self.store.key(name)[3] == "prepared":
                    self.store.advance(name, "prepared", "published")
            content = json.dumps(
                {
                    "answer": candidate.to_wire(max_size=65535).hex(),
                    "evidence": [
                        value.to_wire(max_size=65535).hex() for value in transformed.values()
                    ],
                },
                separators=(",", ":"),
            ).encode()
            if len(content) > 1048576:
                raise RequestDenied("dns_publication_wire_limit")
            self.store.commit_publication(
                "dns-generation/" + uuid4().hex,
                content,
                tuple(sorted(dependencies)),
                horizon,
            )
            for name in dependencies:
                if self.store.key(name)[3] == "published":
                    self.store.advance(name, "published", "active")
            for plan in plans:
                self.lifecycle.commit(plan)
            self.store.prune_publications("dns-generation/", now=time.time())
            self.ech.collect(now=time.time())
            if time.monotonic() >= deadline:
                raise RequestDenied("dns_resolution_deadline")
            return render(query, candidate, checked, safe_udp_payload=self.safe_udp_payload)
        except DNSSECUnrepresentable as exc:
            if time.monotonic() >= deadline:
                raise RequestDenied("dns_resolution_deadline") from None
            logging.getLogger(__name__).warning("synthetic DNS construction unavailable: %s", exc)
            return fallback(query, authentication, safe_udp_payload=self.safe_udp_payload)
        except StateUnavailable:
            # State/quota/custody failure is not a fabricated DNSSEC response.
            raise RequestDenied("dns_persistent_state_unavailable") from None

    def _construct(
        self,
        messages: list[dns.message.Message],
        original: dns.message.Message,
        root_keys: dns.rrset.RRset,
        job: ResolutionJob,
        budget: CryptoBudget,
        *,
        overlap: bool = False,
    ) -> tuple[
        dict[QueryKey, dns.message.Message],
        dns.message.Message,
        set[str],
        float,
        tuple[ZonePlan, ...],
    ]:
        if len(messages) > 256:
            raise RequestDenied("dns_candidate_message_limit")
        transformer = DNSSECTransformer(self.identities, job, budget)
        acquired: dict[QueryKey, dns.message.Message] = {}
        for message in messages:
            key = _query(message)
            prior = acquired.get(key)
            if prior is not None and any(
                len(left) != len(right) or any(item not in right for item in left)
                for left, right in (
                    (prior.answer, message.answer),
                    (prior.authority, message.authority),
                )
            ):
                raise DNSSECUnrepresentable("conflicting DNS generation evidence")
            acquired[key] = message
        mappings: dict[dns.name.Name, KeySubstitution] = {}
        for message in acquired.values():
            if message.question[0].rdtype == dns.rdatatype.DNSKEY:
                keys = exact(message, message.question[0].name, dns.rdatatype.DNSKEY)
                if keys:
                    mappings[keys.name] = transformer.keys(keys)
                elif not message.answer and any(
                    rrset.rdtype == dns.rdatatype.SOA and rrset.name == message.question[0].name
                    for rrset in message.authority
                ):
                    empty = dns.rrset.RRset(
                        message.question[0].name, dns.rdataclass.IN, dns.rdatatype.DNSKEY
                    )
                    mappings[empty.name] = KeySubstitution(empty, copy.deepcopy(empty), ())
        now = time.time()
        # Retained keys NEVER fill missing fresh evidence or add a valid path
        # to a defective view. Only the fully authenticated view admits overlap.
        plans = tuple(
            self.lifecycle.plan(zone, mapping.identities, now=now)
            for zone, mapping in mappings.items()
            if overlap and mapping.identities
        )
        old = {identity.zone: plan.overlap for plan in plans for identity in plan.overlap}
        for zone, identities in old.items():
            mapping = mappings[zone]
            combined = copy.deepcopy(mapping.synthetic)
            for identity in identities:
                combined.add(identity.dnskey, combined.ttl)
            tags = {(key.algorithm, dns.dnssec.key_id(key)) for key in combined}
            if len(tags) != len(combined):
                raise DNSSECUnrepresentable("overlap DNSKEY tag collision")
            mappings[zone] = KeySubstitution(mapping.original, combined, mapping.identities)
        root_mapping = mappings.get(dns.name.root)
        if root_mapping is None or root_mapping.original != root_keys:
            raise DNSSECUnrepresentable("root generation evidence mismatch")
        # Root identity is stable independently of upstream root KSK/ZSK changes.
        # This bridge is permitted only after successful upstream root validation.
        combined = copy.deepcopy(root_mapping.synthetic)
        combined.add(self.root.dnskey, combined.ttl)
        mappings[dns.name.root] = KeySubstitution(
            root_mapping.original, combined, root_mapping.identities
        )
        dependencies = {
            self.root.name,
            *(identity.name for m in mappings.values() for identity in m.identities),
            *(identity.name for values in old.values() for identity in values),
        }
        horizon = now + 1
        transformed: dict[QueryKey, dns.message.Message] = {}

        def convert(message: dns.message.Message) -> dns.message.Message:
            nonlocal horizon
            result = dns.message.make_response(
                dns.message.make_query(message.question[0].name, message.question[0].rdtype)
            )
            result.set_rcode(message.rcode())
            result.flags = message.flags & ~dns.flags.AD
            for source, target in (
                (message.answer, result.answer),
                (message.authority, result.authority),
            ):
                for rrset in source:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        continue
                    changed = copy.deepcopy(rrset)
                    if rrset.rdtype == dns.rdatatype.DNSKEY:
                        if rrset.name not in mappings:
                            raise DNSSECUnrepresentable("unacquired DNSKEY substitution")
                        changed = copy.deepcopy(mappings[rrset.name].synthetic)
                    elif rrset.rdtype == dns.rdatatype.DS:
                        if rrset.name not in mappings:
                            raise DNSSECUnrepresentable("absent delegation key construction")
                        delegated = transformer.delegation(rrset, mappings[rrset.name])
                        changed = delegated.records
                        if not delegated.before.failures and delegated.before.matched:
                            for identity in old.get(rrset.name, ()):
                                for digest in {record.digest_type for record in rrset}:
                                    budget.consume()
                                    changed.add(
                                        dns.dnssec.make_ds(
                                            rrset.name, identity.dnskey, digest, validating=True
                                        ),
                                        changed.ttl,
                                    )
                    elif rrset.rdtype in (dns.rdatatype.HTTPS, dns.rdatatype.SVCB):
                        publication = self.ech.rewrite(rrset, now=now)
                        changed = publication.records
                        if publication.dependency is not None:
                            dependencies.add(publication.dependency)
                            horizon = max(horizon, publication.retain_until)
                    target.append(changed)
                    horizon = max(horizon, now + rrset.ttl)
                    sigsets = [
                        item
                        for item in source
                        if item.name == rrset.name
                        and item.rdtype == dns.rdatatype.RRSIG
                        and item.covers == rrset.rdtype
                    ]
                    if len(sigsets) > 1:
                        raise DNSSECUnrepresentable("ambiguous signature RRset")
                    if sigsets:
                        sigs = sigsets[0]
                        signers = {sig.signer for sig in sigs}
                        converted = dns.rrset.RRset(
                            rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, rrset.rdtype
                        )
                        for signer in signers:
                            mapping = mappings.get(signer)
                            if mapping is None:
                                raise DNSSECUnrepresentable("unacquired signature keys")
                            selected = dns.rrset.from_rdata(
                                sigs.name, sigs.ttl, *(sig for sig in sigs if sig.signer == signer)
                            )
                            substitution = transformer.signatures(
                                rrset, changed, selected, mapping, now=now
                            )
                            signature = substitution.signatures
                            if signature is not None:
                                for sig in signature:
                                    converted.add(sig, signature.ttl)
                            if substitution.before.valid and not substitution.before.failures:
                                # Double-sign the same transformed bytes and exact
                                # supported upstream validity interval. No repair
                                # signatures are emitted for an invalid RRset.
                                for identity in old.get(signer, ()):
                                    template = selected[0]
                                    signing_set = copy.deepcopy(changed)
                                    signing_set.ttl = template.original_ttl
                                    if template.labels < len(signing_set.name.labels) - 1:
                                        signing_set.name = dns.name.Name(
                                            (b"*",)
                                            + signing_set.name.labels[-template.labels - 1 :]
                                        )
                                    budget.consume()
                                    converted.add(
                                        identity.sign(
                                            signing_set,
                                            inception=template.inception,
                                            expiration=template.expiration,
                                        ),
                                        selected.ttl,
                                    )
                            for sig in selected:
                                horizon = max(horizon, now + sig.original_ttl, sig.expiration)
                        target.append(converted)
                    if rrset.name == dns.name.root and rrset.rdtype == dns.rdatatype.DNSKEY:
                        self._bridge(changed, target, now=now, budget=budget)
            return result

        for key, message in acquired.items():
            transformed[key] = convert(message)
        candidate = convert(original)
        return transformed, candidate, dependencies, horizon, plans

    def _bridge(
        self,
        keys: dns.rrset.RRset,
        section: list[dns.rrset.RRset],
        *,
        now: float,
        budget: CryptoBudget,
    ) -> None:
        budget.consume()
        signature = self.root.sign(
            keys, inception=int(now) - 1, expiration=int(now) + max(1, keys.ttl)
        )
        existing = [
            rrset
            for rrset in section
            if rrset.name == dns.name.root
            and rrset.rdtype == dns.rdatatype.RRSIG
            and rrset.covers == dns.rdatatype.DNSKEY
        ]
        if existing:
            existing[0].add(signature, keys.ttl)
        else:
            section.append(dns.rrset.from_rdata(dns.name.root, keys.ttl, signature))
