"""Narrow issuer-signed OCSP evidence verification for RFC 3161 TSA certificates.

Only a single SHA-256 CertID response signed directly by the issuing CA using
RSA/SHA-256 is accepted. Delegated responders are deliberately unsupported.
A GOOD response is never promoted into historical proof of non-revocation.
"""
from __future__ import annotations

from datetime import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import ocsp

from experiments.rfc3161_revocation_identity import (
    check_tsa_issuer_identity,
    sha256,
    single_pem_certificate,
)


_MAX_OCSP_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_OCSP_REQUEST_BYTES = 1024 * 1024
_RSA_SHA256_OID = "1.2.840.113549.1.1.11"
_OCSP_NONCE_OID = "1.3.6.1.5.5.7.48.1.2"


def _nonce(extensions, field: str) -> bytes | None:
    found = None
    for extension in extensions:
        if extension.oid.dotted_string == _OCSP_NONCE_OID:
            if extension.critical:
                raise ValueError(f"{field} OCSP nonce must be non-critical.")
            if found is not None:
                raise ValueError(f"{field} contains duplicate OCSP nonce extensions.")
            found = extension.value.nonce
        else:
            raise ValueError(f"{field} contains an unsupported extension.")
    return found


def _assert_issuer_can_sign_ocsp(issuer_certificate: x509.Certificate) -> None:
    try:
        key_usage = issuer_certificate.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("issuer certificate has no KeyUsage extension.") from exc
    if not key_usage.digital_signature:
        raise ValueError("issuer certificate is not authorized for OCSP digital signatures.")


def verify_tsa_ocsp_evidence(
    timestamp_result: dict,
    tsa_certificate_pem: bytes,
    issuer_certificate_pem: bytes,
    ocsp_response_der: bytes,
    ocsp_request_der: bytes | None = None,
    *,
    timestamp_verification_inputs: dict,
) -> dict:
    """Authenticate one issuer-signed OCSP response for the verified TSA cert.

    A GOOD response is reported only as a status assertion at thisUpdate. It
    never establishes historical non-revocation. A signed permanent
    revocationTime at or before the token's asserted genTime can establish a
    revocation-by-target assertion. Delegated responders and non-RSA/SHA-256
    response signatures are not accepted by this first profile.
    """
    if not isinstance(ocsp_response_der, bytes) or not ocsp_response_der:
        raise ValueError("ocsp_response_der must be non-empty DER bytes.")
    if len(ocsp_response_der) > _MAX_OCSP_RESPONSE_BYTES:
        raise ValueError("ocsp_response_der exceeds 2 MiB.")
    if ocsp_request_der is not None and (
        not isinstance(ocsp_request_der, bytes)
        or not ocsp_request_der
        or len(ocsp_request_der) > _MAX_OCSP_REQUEST_BYTES
    ):
        raise ValueError("ocsp_request_der must be non-empty DER bytes no larger than 1 MiB.")

    tsa_certificate = single_pem_certificate(
        tsa_certificate_pem, "tsa_certificate_pem"
    )
    issuer_certificate = single_pem_certificate(
        issuer_certificate_pem, "issuer_certificate_pem"
    )
    target_time = check_tsa_issuer_identity(
        timestamp_result, tsa_certificate, issuer_certificate,
        timestamp_verification_inputs,
    )
    _assert_issuer_can_sign_ocsp(issuer_certificate)

    response = ocsp.load_der_ocsp_response(ocsp_response_der)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError("OCSP response status is not SUCCESSFUL.")
    if response.certificates:
        raise ValueError("delegated OCSP responder certificates are unsupported.")

    if response.responder_name is not None:
        if response.responder_name != issuer_certificate.subject:
            raise ValueError("OCSP responder name does not match the bound issuer certificate.")
        responder_id_type = "NAME"
    else:
        # RFC 6960 ResponderID byKey is the SHA-1 hash of the responder
        # public-key BIT STRING, not the certificate's optional SKI extension.
        expected_responder_key_hash = x509.SubjectKeyIdentifier.from_public_key(
            issuer_certificate.public_key()
        ).digest
        if response.responder_key_hash != expected_responder_key_hash:
            raise ValueError("OCSP responder key hash does not match the bound issuer key.")
        responder_id_type = "KEY_HASH"

    issuer_key = issuer_certificate.public_key()
    if not isinstance(issuer_key, rsa.RSAPublicKey):
        raise ValueError("only issuer RSA keys are supported by this OCSP profile.")
    if (
        response.signature_algorithm_oid.dotted_string != _RSA_SHA256_OID
        or response.signature_hash_algorithm is None
        or response.signature_hash_algorithm.name != "sha256"
    ):
        raise ValueError("only RSA/SHA-256 OCSP response signatures are supported.")
    try:
        issuer_key.verify(
            response.signature,
            response.tbs_response_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as exc:
        raise ValueError("OCSP response signature does not verify under the bound issuer.") from exc

    single_responses = list(response.responses)
    if len(single_responses) != 1:
        raise ValueError("exactly one OCSP SingleResponse is required.")
    single = single_responses[0]
    if single.hash_algorithm.name != "sha256":
        raise ValueError("only SHA-256 OCSP CertID values are supported.")

    expected_request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(tsa_certificate, issuer_certificate, hashes.SHA256())
        .build()
    )
    expected_cert_id = (
        single.serial_number == expected_request.serial_number
        and single.issuer_name_hash == expected_request.issuer_name_hash
        and single.issuer_key_hash == expected_request.issuer_key_hash
        and single.hash_algorithm.name == expected_request.hash_algorithm.name
    )
    if not expected_cert_id:
        raise ValueError("OCSP CertID does not identify the exact TSA certificate and issuer.")

    request_nonce = None
    if ocsp_request_der is not None:
        request = ocsp.load_der_ocsp_request(ocsp_request_der)
        if (
            request.serial_number != expected_request.serial_number
            or request.issuer_name_hash != expected_request.issuer_name_hash
            or request.issuer_key_hash != expected_request.issuer_key_hash
            or request.hash_algorithm.name != "sha256"
        ):
            raise ValueError("OCSP request CertID does not identify the exact TSA certificate.")
        request_nonce = _nonce(request.extensions, "request")
    response_nonce = _nonce(response.extensions, "response")
    if request_nonce is None and response_nonce is not None:
        raise ValueError("OCSP response nonce cannot be matched without a request nonce.")
    if request_nonce is not None and response_nonce != request_nonce:
        raise ValueError("OCSP response nonce does not match the supplied request nonce.")
    nonce_binding = "MATCH" if request_nonce is not None else "NOT_USED"

    if list(response.single_extensions):
        raise ValueError("OCSP SingleResponse extensions are unsupported in this profile.")

    this_update = single.this_update_utc
    next_update = single.next_update_utc
    produced_at = response.produced_at_utc
    if next_update is None or next_update <= this_update:
        raise ValueError("OCSP response must contain an increasing thisUpdate/nextUpdate interval.")
    if produced_at < this_update or produced_at >= next_update:
        raise ValueError("OCSP producedAt must fall within the signed status interval.")

    status = single.certificate_status
    revocation_time = single.revocation_time_utc
    reason = single.revocation_reason
    if status == ocsp.OCSPCertStatus.REVOKED:
        if revocation_time is None:
            raise ValueError("REVOKED OCSP status requires revocationTime.")
        if revocation_time > this_update:
            raise ValueError("OCSP revocationTime is later than thisUpdate.")
        if reason == x509.ReasonFlags.remove_from_crl:
            raise ValueError("removeFromCRL is unsupported as an OCSP revocation reason.")
    elif revocation_time is not None:
        raise ValueError("non-REVOKED OCSP status must not carry revocationTime.")

    status_at_target = "NOT_ESTABLISHED"
    historical_assurance = "NOT_ESTABLISHED"
    if status == ocsp.OCSPCertStatus.GOOD:
        if this_update <= target_time < next_update:
            status_at_target = "GOOD_AT_OCSP_THIS_UPDATE_ONLY"
        else:
            status_at_target = "EVIDENCE_TIME_INCOMPATIBLE"
    elif status == ocsp.OCSPCertStatus.UNKNOWN:
        status_at_target = "UNKNOWN"
    elif status == ocsp.OCSPCertStatus.REVOKED:
        if reason == x509.ReasonFlags.certificate_hold:
            status_at_target = "CERTIFICATE_HOLD_REPORTED_TARGET_STATUS_NOT_ESTABLISHED"
        elif revocation_time <= target_time:
            status_at_target = "REVOKED_AT_OR_BEFORE_TARGET"
            historical_assurance = "REVOKED_BY_TARGET_TIME_UNDER_SIGNED_OCSP_ASSERTION"
        else:
            status_at_target = "REVOCATION_AFTER_TARGET_REPORTED"

    return {
        "result_version": "rfc3161-tsa-revocation-verification-result/v1-draft",
        "evidence_type": "OCSP_BASIC_RESPONSE",
        "ocsp_evidence_verification": "VALID_RELATIVE_TO_BOUND_ISSUER_CERTIFICATE",
        "tsa_certificate_identity_binding": "MATCH",
        "ocsp_signature": "VALID",
        "responder_authorization": "ISSUING_CA_DIRECTLY_SIGNED",
        "responder_id_type": responder_id_type,
        "ocsp_cert_id_binding": "MATCH",
        "cert_id_hash_algorithm": single.hash_algorithm.name,
        "serial_hex": format(single.serial_number, "x"),
        "issuer_name_hash": single.issuer_name_hash.hex(),
        "issuer_key_hash": single.issuer_key_hash.hex(),
        "nonce_binding": nonce_binding,
        "ocsp_response_der_sha256": sha256(ocsp_response_der),
        "produced_at_utc": produced_at.isoformat().replace("+00:00", "Z"),
        "this_update_utc": this_update.isoformat().replace("+00:00", "Z"),
        "next_update_utc": next_update.isoformat().replace("+00:00", "Z"),
        "ocsp_time_window_covers_target": this_update <= target_time < next_update,
        "evidence_time_basis": "RESPONDER_ASSERTED_PRODUCED_AT_THIS_UPDATE_NEXT_UPDATE",
        "target_time_utc": target_time.isoformat().replace("+00:00", "Z"),
        "target_time_basis": "TSA_ASSERTED_GEN_TIME",
        "status_at_evidence_time": status.name,
        "status_at_target_time": status_at_target,
        "revocation_time_utc": (
            revocation_time.isoformat().replace("+00:00", "Z")
            if revocation_time is not None else None
        ),
        "revocation_reason": reason.name if reason is not None else None,
        "historical_revocation_assurance": historical_assurance,
        "good_status_limitation": (
            "OCSP_GOOD_AT_THIS_UPDATE_DOES_NOT_ESTABLISH_HISTORICAL_NON_REVOCATION"
        ),
        "issuer_trust": "REVERIFIED_RELATIVE_TO_CALLER_SUPPLIED_PINNED_TIMESTAMP_ANCHOR",
    }
