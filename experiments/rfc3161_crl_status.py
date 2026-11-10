"""Narrow RFC 3161 TSA CRL evidence verification.

This module accepts only a complete, direct, all-reasons CRL signed by the
exact issuer certificate bound by a successful prior timestamp verification.
It deliberately does not infer that absence from one CRL proves historical
non-revocation.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization


_MAX_CRL_BYTES = 2 * 1024 * 1024
_CRL_NUMBER_OID = "2.5.29.20"
_AUTHORITY_KEY_ID_OID = "2.5.29.35"
_ISSUING_DISTRIBUTION_POINT_OID = "2.5.29.28"
_DELTA_CRL_INDICATOR_OID = "2.5.29.27"
_FRESHEST_CRL_OID = "2.5.29.46"
_CRL_REASON_OID = "2.5.29.21"
_INVALIDITY_DATE_OID = "2.5.29.24"
_CERTIFICATE_ISSUER_OID = "2.5.29.29"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _single_pem_certificate(pem: bytes, field: str) -> x509.Certificate:
    if not isinstance(pem, bytes) or not pem:
        raise ValueError(f"{field} must be non-empty PEM bytes.")
    if (
        pem.count(b"-----BEGIN CERTIFICATE-----") != 1
        or pem.count(b"-----END CERTIFICATE-----") != 1
    ):
        raise ValueError(f"{field} must contain exactly one PEM certificate.")
    return x509.load_pem_x509_certificate(pem)


def _utc_instant(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ValueError("timestamp result must contain a whole-second UTC genTime.")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _subject_key_identifier(certificate: x509.Certificate) -> bytes:
    try:
        return certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
    except x509.ExtensionNotFound:
        return x509.SubjectKeyIdentifier.from_public_key(
            certificate.public_key()
        ).digest


def _check_identity_binding(
    timestamp_result: dict,
    tsa_certificate: x509.Certificate,
    issuer_certificate: x509.Certificate,
) -> None:
    identity = timestamp_result.get("tsa_signer_certificate")
    if not isinstance(identity, dict):
        raise ValueError("timestamp result has no extracted TSA signer identity.")
    tsa_der = tsa_certificate.public_bytes(serialization.Encoding.DER)
    issuer_der = issuer_certificate.public_bytes(serialization.Encoding.DER)
    issuer_name_der = tsa_certificate.issuer.public_bytes()
    issuer_spki_der = issuer_certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tsa_spki_der = tsa_certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected = {
        "certificate_der_sha256": _sha256(tsa_der),
        "subject_spki_sha256": _sha256(tsa_spki_der),
        "issuer_name_der_sha256": _sha256(issuer_name_der),
        "issuer_certificate_der_sha256": _sha256(issuer_der),
        "issuer_spki_sha256": _sha256(issuer_spki_der),
        "serial_hex": format(tsa_certificate.serial_number, "x"),
    }
    if any(identity.get(key) != value for key, value in expected.items()):
        raise ValueError("supplied TSA/issuer certificates do not match the prior timestamp identity.")
    if tsa_certificate.issuer != issuer_certificate.subject:
        raise ValueError("TSA certificate issuer name does not match supplied issuer subject.")
    try:
        authority_key_id = tsa_certificate.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        authority_key_id = None
    if authority_key_id is not None and authority_key_id.key_identifier is not None:
        if authority_key_id.key_identifier != _subject_key_identifier(issuer_certificate):
            raise ValueError("TSA certificate Authority Key Identifier does not match supplied issuer.")
    try:
        basic_constraints = issuer_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("issuer certificate has no BasicConstraints extension.") from exc
    if not basic_constraints.ca:
        raise ValueError("issuer certificate is not a CA certificate.")
    try:
        tsa_certificate.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        )
    except x509.ExtensionNotFound:
        pass
    else:
        raise ValueError("TSA certificate CRL distribution-point scope matching is unsupported.")
    try:
        key_usage = issuer_certificate.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("issuer certificate has no KeyUsage extension.") from exc
    if not key_usage.crl_sign:
        raise ValueError("issuer certificate is not authorized for CRL signing.")


def verify_tsa_crl_evidence(
    timestamp_result: dict,
    tsa_certificate_pem: bytes,
    issuer_certificate_pem: bytes,
    crl_der: bytes,
) -> dict:
    """Authenticate a narrow direct-CRL evidence item for a verified TSA token.

    A serial absent from a CRL is reported only as NOT_LISTED_AT_CRL_THIS_UPDATE.
    It is never promoted to proof of historical non-revocation. A signed
    revocationDate at or before the token's asserted genTime is reported as a
    revocation assertion by that time.
    """
    if not isinstance(timestamp_result, dict):
        raise ValueError("timestamp_result must be an object.")
    if timestamp_result.get("timestamp_verification") != "VALID":
        raise ValueError("a VALID prior RFC 3161 timestamp result is required.")
    if timestamp_result.get("tsa_signer_certificate_identity") != "EXTRACTED":
        raise ValueError("an EXTRACTED TSA signer identity is required.")
    if not isinstance(crl_der, bytes) or not crl_der or len(crl_der) > _MAX_CRL_BYTES:
        raise ValueError("crl_der must be non-empty DER bytes no larger than 2 MiB.")

    target_time = _utc_instant(timestamp_result.get("tsa_asserted_gen_time_utc"))
    tsa_certificate = _single_pem_certificate(tsa_certificate_pem, "tsa_certificate_pem")
    issuer_certificate = _single_pem_certificate(
        issuer_certificate_pem, "issuer_certificate_pem"
    )
    _check_identity_binding(timestamp_result, tsa_certificate, issuer_certificate)

    crl = x509.load_der_x509_crl(crl_der)
    if crl.issuer != issuer_certificate.subject:
        raise ValueError("CRL issuer name does not match the bound issuer certificate.")
    if not crl.is_signature_valid(issuer_certificate.public_key()):
        raise ValueError("CRL signature does not verify under the bound issuer certificate.")

    try:
        crl_number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound as exc:
        raise ValueError("CRLNumber extension is required.") from exc
    try:
        crl_aki = crl.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("CRL Authority Key Identifier extension is required.") from exc
    if crl_aki.key_identifier is None or crl_aki.key_identifier != _subject_key_identifier(
        issuer_certificate
    ):
        raise ValueError("CRL Authority Key Identifier does not match the bound issuer key.")

    allowed_crl_extensions = {_CRL_NUMBER_OID, _AUTHORITY_KEY_ID_OID}
    for extension in crl.extensions:
        if extension.oid.dotted_string in {
            _ISSUING_DISTRIBUTION_POINT_OID,
            _DELTA_CRL_INDICATOR_OID,
            _FRESHEST_CRL_OID,
        }:
            raise ValueError("scoped, delta or freshest-CRL evidence is unsupported.")
        if extension.oid.dotted_string not in allowed_crl_extensions:
            raise ValueError("CRL contains an unsupported extension.")
        if extension.critical:
            raise ValueError("CRLNumber and AuthorityKeyIdentifier must be non-critical.")

    this_update = crl.last_update_utc
    next_update = crl.next_update_utc
    if this_update is None or next_update is None or next_update <= this_update:
        raise ValueError("CRL must contain an increasing thisUpdate/nextUpdate interval.")

    matching_entries = [
        entry for entry in crl
        if entry.serial_number == tsa_certificate.serial_number
    ]
    if len(matching_entries) > 1:
        raise ValueError("CRL contains duplicate entries for the TSA certificate serial.")
    revoked_entry = matching_entries[0] if matching_entries else None
    revocation_time = None
    revocation_reason = None
    status_at_target = "NOT_ESTABLISHED"
    historical_assurance = "NOT_ESTABLISHED"

    if revoked_entry is not None:
        for extension in revoked_entry.extensions:
            if extension.oid.dotted_string == _CERTIFICATE_ISSUER_OID:
                raise ValueError("indirect CRL certificateIssuer entries are unsupported.")
            if extension.oid.dotted_string not in {
                _CRL_REASON_OID, _INVALIDITY_DATE_OID
            }:
                if extension.critical:
                    raise ValueError("revoked entry contains an unsupported critical extension.")
                raise ValueError("revoked entry contains an unsupported extension.")
        try:
            reason = revoked_entry.extensions.get_extension_for_class(
                x509.CRLReason
            ).value.reason
            revocation_reason = reason.name
            if reason == x509.ReasonFlags.remove_from_crl:
                raise ValueError("removeFromCRL is unsupported in this complete-CRL profile.")
        except x509.ExtensionNotFound:
            pass
        revocation_time = revoked_entry.revocation_date_utc
        if revocation_time > this_update:
            raise ValueError("CRL entry revocationDate is later than CRL thisUpdate.")
        if revocation_time <= target_time:
            status_at_target = "REVOKED_AT_OR_BEFORE_TARGET"
            historical_assurance = "REVOKED_BY_TARGET_TIME_UNDER_SIGNED_CRL_ASSERTION"
        else:
            status_at_target = "REVOCATION_AFTER_TARGET_REPORTED"
    elif this_update <= target_time < next_update:
        status_at_target = "NOT_LISTED_AT_CRL_THIS_UPDATE"

    return {
        "crl_evidence_verification": "VALID_RELATIVE_TO_BOUND_ISSUER_CERTIFICATE",
        "tsa_certificate_identity_binding": "MATCH",
        "crl_signature": "VALID",
        "crl_scope": "DIRECT_COMPLETE_ALL_REASONS_ONLY",
        "crl_number": crl_number,
        "crl_this_update_utc": this_update.isoformat().replace("+00:00", "Z"),
        "crl_next_update_utc": next_update.isoformat().replace("+00:00", "Z"),
        "target_time_utc": target_time.isoformat().replace("+00:00", "Z"),
        "target_time_basis": "TSA_ASSERTED_GEN_TIME",
        "status_at_target_time": status_at_target,
        "revocation_time_utc": (
            revocation_time.isoformat().replace("+00:00", "Z")
            if revocation_time is not None else None
        ),
        "revocation_reason": revocation_reason,
        "historical_revocation_assurance": historical_assurance,
        "absence_interpretation": (
            "NOT_LISTED_AT_CRL_THIS_UPDATE_IS_NOT_PROOF_OF_HISTORICAL_NON_REVOCATION"
        ),
        "issuer_trust": "BOUND_TO_PRIOR_TIMESTAMP_RESULT_NOT_REAUTHENTICATED_HERE",
    }
