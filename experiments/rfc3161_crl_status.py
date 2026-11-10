"""Narrow RFC 3161 TSA CRL evidence verification.

This module accepts only a complete, direct, all-reasons CRL signed by the
exact issuer certificate bound by a successful prior timestamp verification.
It deliberately does not infer that absence from one CRL proves historical
non-revocation.
"""
from __future__ import annotations

from cryptography import x509

from experiments.rfc3161_revocation_identity import (
    check_tsa_issuer_identity,
    sha256,
    single_pem_certificate,
    subject_key_identifier,
)


_MAX_CRL_BYTES = 2 * 1024 * 1024
_CRL_NUMBER_OID = "2.5.29.20"
_AUTHORITY_KEY_ID_OID = "2.5.29.35"
_ISSUING_DISTRIBUTION_POINT_OID = "2.5.29.28"
_DELTA_CRL_INDICATOR_OID = "2.5.29.27"
_FRESHEST_CRL_OID = "2.5.29.46"
_CRL_REASON_OID = "2.5.29.21"
_INVALIDITY_DATE_OID = "2.5.29.24"
_CERTIFICATE_ISSUER_OID = "2.5.29.29"


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
    if not isinstance(crl_der, bytes) or not crl_der or len(crl_der) > _MAX_CRL_BYTES:
        raise ValueError("crl_der must be non-empty DER bytes no larger than 2 MiB.")

    tsa_certificate = single_pem_certificate(tsa_certificate_pem, "tsa_certificate_pem")
    issuer_certificate = single_pem_certificate(
        issuer_certificate_pem, "issuer_certificate_pem"
    )
    target_time = check_tsa_issuer_identity(
        timestamp_result, tsa_certificate, issuer_certificate
    )
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
    if crl_aki.key_identifier is None or crl_aki.key_identifier != subject_key_identifier(
        issuer_certificate
    ):
        raise ValueError("CRL Authority Key Identifier does not match the bound issuer key.")

    has_aki_serial = crl_aki.authority_cert_serial_number is not None
    has_aki_issuer = crl_aki.authority_cert_issuer is not None
    if has_aki_serial != has_aki_issuer:
        raise ValueError("CRL Authority Key Identifier issuer and serial must appear together.")
    if has_aki_serial:
        directory_names = [
            name.value for name in crl_aki.authority_cert_issuer
            if isinstance(name, x509.DirectoryName)
        ]
        if (
            crl_aki.authority_cert_serial_number != issuer_certificate.serial_number
            or not directory_names
            or issuer_certificate.issuer not in directory_names
        ):
            raise ValueError("CRL Authority Key Identifier issuer/serial does not match the bound issuer.")

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

    # certificateIssuer changes the interpretation of subsequent entries
    # in an indirect CRL. Reject it anywhere in the list, not only on the TSA
    # serial: otherwise an unrelated entry could silently change list scope.
    for entry in crl:
        if any(
            extension.oid.dotted_string == _CERTIFICATE_ISSUER_OID
            for extension in entry.extensions
        ):
            raise ValueError("indirect CRL certificateIssuer entries are unsupported.")

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
        reason = None
        for extension in revoked_entry.extensions:
            if extension.oid.dotted_string == _INVALIDITY_DATE_OID:
                raise ValueError("CRL InvalidityDate semantics are unsupported in this profile.")
            if extension.oid.dotted_string != _CRL_REASON_OID:
                if extension.critical:
                    raise ValueError("revoked entry contains an unsupported critical extension.")
                raise ValueError("revoked entry contains an unsupported extension.")
            if extension.critical:
                raise ValueError("CRLReason entry extensions must be non-critical.")
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
        if reason == x509.ReasonFlags.certificate_hold:
            status_at_target = "CERTIFICATE_HOLD_REPORTED_TARGET_STATUS_NOT_ESTABLISHED"
        elif revocation_time <= target_time:
            status_at_target = "REVOKED_AT_OR_BEFORE_TARGET"
            historical_assurance = "REVOKED_BY_TARGET_TIME_UNDER_SIGNED_CRL_ASSERTION"
        else:
            status_at_target = "REVOCATION_AFTER_TARGET_REPORTED"
    elif this_update <= target_time < next_update:
        status_at_target = "NOT_LISTED_AT_CRL_THIS_UPDATE"

    return {
        "result_version": "rfc3161-tsa-revocation-verification-result/v1-draft",
        "evidence_type": "CRL",
        "crl_evidence_verification": "VALID_RELATIVE_TO_BOUND_ISSUER_CERTIFICATE",
        "tsa_certificate_identity_binding": "MATCH",
        "crl_signature": "VALID",
        "crl_scope": "DIRECT_COMPLETE_ALL_REASONS_ONLY",
        "crl_der_sha256": sha256(crl_der),
        "crl_number": crl_number,
        "crl_this_update_utc": this_update.isoformat().replace("+00:00", "Z"),
        "crl_next_update_utc": next_update.isoformat().replace("+00:00", "Z"),
        "crl_time_window_covers_target": this_update <= target_time < next_update,
        "evidence_time_basis": "ISSUER_ASSERTED_CRL_THIS_UPDATE_NEXT_UPDATE",
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
