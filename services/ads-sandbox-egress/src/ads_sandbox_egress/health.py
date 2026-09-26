"""Bounded real local enforcement health; never upstream Internet availability."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import dns.dnssec
import dns.rrset

from ads_sandbox_egress.certificates import EgressSigner
from ads_sandbox_egress.configuration import PolicyStore
from ads_sandbox_egress.crl import CRLAuthority, CRLRepository
from ads_sandbox_egress.crl_http import LocalCRLService
from ads_sandbox_egress.dns_transport import DNSTransport
from ads_sandbox_egress.dnssec_identity import DNSSECIdentities, SigningIdentity
from ads_sandbox_egress.dnssec_lifecycle import DNSSECLifecycle
from ads_sandbox_egress.ech_lifecycle import ECHLifecycle
from ads_sandbox_egress.helper import Helper
from ads_sandbox_egress.identity_store import IdentityStore
from ads_sandbox_egress.interception import Interception


class EnforcementHealth:
    def __init__(
        self,
        policies: PolicyStore,
        state: IdentityStore,
        root: SigningIdentity,
        signer: EgressSigner,
        helper: Helper,
        dns: DNSTransport,
        interception: Interception,
        ech: ECHLifecycle,
        crls: CRLRepository,
        crl_service: LocalCRLService,
    ) -> None:
        self.policies, self.state, self.root, self.signer = policies, state, root, signer
        self.helper, self.dns, self.interception, self.ech = helper, dns, interception, ech
        self.crls, self.crl_service = crls, crl_service
        self._lock = asyncio.Lock()

    async def healthy(self) -> bool:
        if self._lock.locked():
            return False
        async with self._lock:
            if not self.policies.accepting or not self.dns.healthy or not self.crl_service.healthy:
                return False
            listener = self.interception.listener
            if listener is None or not listener.is_serving() or not await self.helper.healthy():
                return False
            if not await self.interception.check():
                return False
            self.signer.require_current()
            # Actual encrypted inventory/key authentication and local signing,
            # independently verified; not a "configured" Boolean or remote query.
            root = DNSSECIdentities(self.state).root(expected_fingerprint=self.root.fingerprint)
            wall_clock = time.time()
            DNSSECLifecycle(DNSSECIdentities(self.state)).collect(now=wall_clock)
            self.ech.collect(now=wall_clock)
            now = int(wall_clock)
            records = root.key_rrset(0)
            signature = root.sign(records, inception=now - 1, expiration=now + 5)
            dns.dnssec.validate(
                records,
                dns.rrset.from_rdata(root.zone, 0, signature),
                {root.zone: records},
                now=now,
            )
            _ = self.ech.context
            # Maintain the real issuer-wide CRL even before policy installation.
            published = self.crls.publish(
                CRLAuthority(self.signer.certificate, self.signer.private_key),
                now=datetime.now(UTC),
            )
            self.crls.get(published.issuer, now=datetime.now(UTC))
            return True
