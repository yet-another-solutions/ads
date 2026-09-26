"""Fresh, issuer-bound direct CRL scope and base/delta evaluation.

No stale CRL cache, signer discovery, issuer repair or unbounded fetch occurs
here. Incomplete scope cannot establish good status. Indirect issuers require
independently authenticated signer evidence, not trust in CRL metadata.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import CRLEntryExtensionOID, ExtensionOID

from ads_sandbox_egress.tls import UnmappableReason, UnmappableTLS

_REASONS = frozenset(
    reason
    for reason in x509.ReasonFlags
    if reason not in (x509.ReasonFlags.unspecified, x509.ReasonFlags.remove_from_crl)
)
_KNOWN = {
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    ExtensionOID.CRL_NUMBER,
    ExtensionOID.DELTA_CRL_INDICATOR,
    ExtensionOID.ISSUING_DISTRIBUTION_POINT,
    ExtensionOID.FRESHEST_CRL,
}


def extension[E: x509.ExtensionType](
    value: x509.Certificate | x509.CertificateRevocationList | x509.RevokedCertificate,
    kind: type[E],
) -> E | None:
    try:
        return value.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None


def _load(wire: bytes, issuer: x509.Certificate, now: datetime) -> x509.CertificateRevocationList:
    if not 1 <= len(wire) <= 2 * 1024**2:
        raise ValueError("CRL byte budget")
    crl = x509.load_der_x509_crl(wire)
    public = issuer.public_key()
    if (
        not isinstance(
            public,
            (
                rsa.RSAPublicKey,
                ec.EllipticCurvePublicKey,
                dsa.DSAPublicKey,
                ed25519.Ed25519PublicKey,
                ed448.Ed448PublicKey,
            ),
        )
        or crl.issuer != issuer.subject
        or not crl.is_signature_valid(public)
        or crl.next_update_utc is None
        or not crl.last_update_utc <= now < crl.next_update_utc
        or len(crl) > 100000
    ):
        raise ValueError("CRL authentication or freshness")
    usage = extension(issuer, x509.KeyUsage)
    if usage is None or not usage.crl_sign:
        raise ValueError("CRL signing usage")
    for item in crl.extensions:
        if item.critical and item.oid not in _KNOWN:
            raise ValueError("unknown critical CRL extension")
    aki = extension(crl, x509.AuthorityKeyIdentifier)
    if aki is not None:
        ski = extension(issuer, x509.SubjectKeyIdentifier)
        expected = ski.digest if ski else x509.SubjectKeyIdentifier.from_public_key(public).digest
        if aki.key_identifier is not None and aki.key_identifier != expected:
            raise ValueError("CRL authority key")
        if aki.authority_cert_serial_number is not None and (
            aki.authority_cert_serial_number != issuer.serial_number
            or x509.DirectoryName(issuer.issuer) not in (aki.authority_cert_issuer or ())
        ):
            raise ValueError("CRL authority certificate")
    return crl


def _names(
    full: Iterable[x509.GeneralName] | None,
    relative: x509.RelativeDistinguishedName | None,
    issuer: x509.Name,
) -> frozenset[x509.GeneralName]:
    if full is not None:
        return frozenset(full)
    if relative is not None:
        return frozenset((x509.DirectoryName(x509.Name([*issuer.rdns, relative])),))
    return frozenset()


def _scope(
    crl: x509.CertificateRevocationList,
    certificate: x509.Certificate,
) -> frozenset[x509.ReasonFlags]:
    idp = extension(crl, x509.IssuingDistributionPoint)
    constraints = extension(certificate, x509.BasicConstraints)
    ca = constraints is not None and constraints.ca
    reasons = _REASONS
    if idp is not None:
        if idp.only_contains_attribute_certs or (
            idp.only_contains_ca_certs and not ca or idp.only_contains_user_certs and ca
        ):
            return frozenset()
        reasons &= idp.only_some_reasons or _REASONS
        names = _names(idp.full_name, idp.relative_name, crl.issuer)
    else:
        names = frozenset()
    points = extension(certificate, x509.CRLDistributionPoints)
    if points is None:
        return frozenset() if names or crl.issuer != certificate.issuer else reasons
    covered: frozenset[x509.ReasonFlags] = frozenset()
    for point in points:
        if point.crl_issuer is not None:
            if (
                idp is None
                or not idp.indirect_crl
                or x509.DirectoryName(crl.issuer) not in point.crl_issuer
            ):
                continue
        elif crl.issuer != certificate.issuer:
            continue
        if names and not names & _names(point.full_name, point.relative_name, certificate.issuer):
            continue
        covered |= reasons & (point.reasons or _REASONS)
    return covered


def _entries(
    crl: x509.CertificateRevocationList,
    now: datetime,
) -> dict[tuple[x509.Name, int], x509.ReasonFlags]:
    result: dict[tuple[x509.Name, int], x509.ReasonFlags] = {}
    delta = extension(crl, x509.DeltaCRLIndicator) is not None
    idp = extension(crl, x509.IssuingDistributionPoint)
    current_issuer = crl.issuer
    for entry in crl:
        issuer_names = extension(entry, x509.CertificateIssuer)
        if issuer_names is not None:
            names = issuer_names.get_values_for_type(x509.DirectoryName)
            if idp is None or not idp.indirect_crl or len(names) != 1:
                raise ValueError("indirect entry issuer")
            if not entry.extensions.get_extension_for_class(x509.CertificateIssuer).critical:
                raise ValueError("noncritical indirect issuer")
            current_issuer = names[0]
        identity = current_issuer, entry.serial_number
        if identity in result or entry.revocation_date_utc > now:
            raise ValueError("CRL duplicate or future entry")
        for item in entry.extensions:
            if item.critical and item.oid not in (
                CRLEntryExtensionOID.CRL_REASON,
                CRLEntryExtensionOID.INVALIDITY_DATE,
                CRLEntryExtensionOID.CERTIFICATE_ISSUER,
            ):
                raise ValueError("CRL entry issuer or critical extension")
        reason_extension = extension(entry, x509.CRLReason)
        reason = reason_extension.reason if reason_extension else x509.ReasonFlags.unspecified
        if reason == x509.ReasonFlags.remove_from_crl and not delta:
            raise ValueError("removeFromCRL without delta")
        result[identity] = reason
    return result


def crl_set_revoked(
    wires: tuple[bytes, ...],
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    *,
    now: datetime,
    signers: tuple[x509.Certificate, ...] = (),
) -> bool:
    try:
        if not 1 <= len(wires) <= 16 or sum(map(len, wires)) > 16 * 1024**2:
            raise ValueError("CRL set budget")
        if len(signers) > 16:
            raise ValueError("CRL signer bound")
        crls_list = []
        for wire in wires:
            if len(wire) > 2 * 1024**2:
                raise ValueError("CRL byte budget")
            untrusted = x509.load_der_x509_crl(wire)
            candidates = []
            for signer in (issuer, *signers):
                if signer.subject != untrusted.issuer or signer in candidates:
                    continue
                if signer != issuer:
                    signer.verify_directly_issued_by(issuer)
                    if not signer.not_valid_before_utc <= now <= signer.not_valid_after_utc:
                        raise ValueError("indirect signer validity")
                candidates.append(signer)
            if len(candidates) != 1:
                raise ValueError("CRL signer unavailable or ambiguous")
            crls_list.append(_load(wire, candidates[0], now))
        crls = tuple(crls_list)
        bases = tuple(crl for crl in crls if extension(crl, x509.DeltaCRLIndicator) is None)
        deltas = tuple(crl for crl in crls if extension(crl, x509.DeltaCRLIndicator) is not None)
        used = set()
        covered: frozenset[x509.ReasonFlags] = frozenset()
        revoked = False
        for base in bases:
            reasons = _scope(base, certificate)
            if not reasons:
                continue
            entries = _entries(base, now)
            number = extension(base, x509.CRLNumber)
            matching = []
            for index, delta in enumerate(deltas):
                minimum = extension(delta, x509.DeltaCRLIndicator)
                delta_number = extension(delta, x509.CRLNumber)
                if (
                    minimum is not None
                    and number is not None
                    and delta_number is not None
                    and minimum.crl_number <= number.crl_number < delta_number.crl_number
                    and extension(delta, x509.IssuingDistributionPoint)
                    == extension(base, x509.IssuingDistributionPoint)
                    and extension(delta, x509.AuthorityKeyIdentifier)
                    == extension(base, x509.AuthorityKeyIdentifier)
                    and delta.issuer == base.issuer
                    and base.last_update_utc <= delta.last_update_utc
                ):
                    used.add(index)
                    matching.append((delta_number.crl_number, delta))
            if matching:
                if len({number for number, _ in matching}) != len(matching):
                    raise ValueError("conflicting delta generations")
                _, latest = max(matching, key=lambda item: item[0])
                for serial, reason in _entries(latest, now).items():
                    if reason == x509.ReasonFlags.remove_from_crl:
                        if entries.get(serial) not in (None, x509.ReasonFlags.certificate_hold):
                            raise ValueError("delta removes permanent revocation")
                        entries.pop(serial, None)
                    else:
                        entries[serial] = reason
            selected_reason = entries.get((certificate.issuer, certificate.serial_number))
            if selected_reason is not None:
                if (
                    selected_reason != x509.ReasonFlags.unspecified
                    and selected_reason not in reasons
                ):
                    raise ValueError("revocation outside authenticated reason scope")
                revoked = True
            covered |= reasons
        if len(used) != len(deltas) or not bases or (not revoked and covered != _REASONS):
            raise ValueError("incomplete CRL scope or missing delta base")
        return revoked
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
        raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS) from None
