"""Shared certificate-identity binding for RFC 3161 revocation evidence."""
from __future__ import annotations

from datetime import datetime
import hashlib
import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization


_MAX_CERTIFICATE_PEM_BYTES = 2 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def single_pem_certificate(pem: bytes, field: str) -> x509.Certificate:
    if not isinstance(pem, bytes) or not pem:
        raise ValueError(f"{field} must be non-empty PEM bytes.")
    if len(pem) > _MAX_CERTIFICATE_PEM_BYTES:
        raise ValueError(f"{field} exceeds 2 MiB.")
    if (
        pem.count(b"-----BEGIN CERTIFICATE-----") != 1
        or pem.count(b"-----END CERTIFICATE-----") != 1
    ):
        raise ValueError(f"{field} must contain exactly one PEM certificate.")
    return x509.load_pem_x509_certificate(pem)


def utc_instant(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ValueError("timestamp result must contain a whole-second UTC genTime.")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def subject_key_identifier(certificate: x509.Certificate) -> bytes:
    try:
        return certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
    except x509.ExtensionNotFound:
        return x509.SubjectKeyIdentifier.from_public_key(
            certificate.public_key()
        ).digest


def require_issuer_certificate_signing_authority(
    issuer_certificate: x509.Certificate,
) -> None:
    """Require CA BasicConstraints and explicit keyCertSign authority."""
    try:
        basic_constraints = issuer_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("issuer certificate has no BasicConstraints extension.") from exc
    if not basic_constraints.ca:
        raise ValueError("issuer certificate is not a CA certificate.")
    try:
        issuer_key_usage = issuer_certificate.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("issuer certificate has no KeyUsage extension.") from exc
    if not issuer_key_usage.key_cert_sign:
        raise ValueError("issuer certificate is not authorized for certificate signing.")


def check_tsa_issuer_identity(
    timestamp_result: dict,
    tsa_certificate: x509.Certificate,
    issuer_certificate: x509.Certificate,
    timestamp_verification_inputs: dict,
) -> datetime:
    """Re-verify original token inputs; never trust a caller-authored result dict."""
    if not isinstance(timestamp_verification_inputs, dict):
        raise ValueError("timestamp_verification_inputs must be an object.")
    required = {"token_der", "data", "trust_anchor_pem", "trust_anchor_pin"}
    optional = {"intermediates_pem", "openssl_binary", "timeout_seconds"}
    missing = required - set(timestamp_verification_inputs)
    extra = set(timestamp_verification_inputs) - required - optional
    if missing or extra:
        raise ValueError(
            "timestamp_verification_inputs has missing or unsupported fields."
        )
    from experiments.rfc3161_timestamp import verify_rfc3161_timestamp
    authenticated_result = verify_rfc3161_timestamp(
        timestamp_verification_inputs["token_der"],
        timestamp_verification_inputs["data"],
        timestamp_verification_inputs["trust_anchor_pem"],
        timestamp_verification_inputs["trust_anchor_pin"],
        intermediates_pem=timestamp_verification_inputs.get("intermediates_pem"),
        openssl_binary=timestamp_verification_inputs.get("openssl_binary", "openssl"),
        timeout_seconds=timestamp_verification_inputs.get("timeout_seconds", 10),
    )
    if (
        authenticated_result.get("timestamp_verification") != "VALID"
        or authenticated_result.get("tsa_signer_certificate_identity") != "EXTRACTED"
    ):
        raise ValueError("original timestamp inputs did not re-verify with extracted signer identity.")
    if not isinstance(timestamp_result, dict) or any(
        timestamp_result.get(key) != authenticated_result.get(key)
        for key in (
            "timestamp_verification",
            "tsa_asserted_gen_time_utc",
            "tsa_signer_certificate_identity",
            "tsa_signer_certificate",
        )
    ):
        raise ValueError("timestamp_result does not match independently re-verified token inputs.")
    timestamp_result = authenticated_result
    if not isinstance(timestamp_result, dict):
        raise ValueError("timestamp_result must be an object.")
    if timestamp_result.get("timestamp_verification") != "VALID":
        raise ValueError("a VALID prior RFC 3161 timestamp result is required.")
    if timestamp_result.get("tsa_signer_certificate_identity") != "EXTRACTED":
        raise ValueError("an EXTRACTED TSA signer identity is required.")
    target_time = utc_instant(timestamp_result.get("tsa_asserted_gen_time_utc"))
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
        "certificate_der_sha256": sha256(tsa_der),
        "subject_spki_sha256": sha256(tsa_spki_der),
        "issuer_name_der_sha256": sha256(issuer_name_der),
        "issuer_certificate_der_sha256": sha256(issuer_der),
        "issuer_spki_sha256": sha256(issuer_spki_der),
        "serial_hex": format(tsa_certificate.serial_number, "x"),
    }
    if any(identity.get(key) != value for key, value in expected.items()):
        raise ValueError(
            "supplied TSA/issuer certificates do not match the prior timestamp identity."
        )
    if tsa_certificate.issuer != issuer_certificate.subject:
        raise ValueError(
            "TSA certificate issuer name does not match supplied issuer subject."
        )
    try:
        authority_key_id = tsa_certificate.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        authority_key_id = None
    if authority_key_id is not None:
        if (
            authority_key_id.key_identifier is not None
            and authority_key_id.key_identifier
            != subject_key_identifier(issuer_certificate)
        ):
            raise ValueError(
                "TSA certificate Authority Key Identifier does not match supplied issuer."
            )
        has_aki_serial = authority_key_id.authority_cert_serial_number is not None
        has_aki_issuer = authority_key_id.authority_cert_issuer is not None
        if has_aki_serial != has_aki_issuer:
            raise ValueError(
                "TSA certificate Authority Key Identifier issuer and serial must appear together."
            )
        if has_aki_serial:
            directory_names = [
                name.value for name in authority_key_id.authority_cert_issuer
                if isinstance(name, x509.DirectoryName)
            ]
            if (
                authority_key_id.authority_cert_serial_number
                != issuer_certificate.serial_number
                or not directory_names
                or issuer_certificate.issuer not in directory_names
            ):
                raise ValueError(
                    "TSA certificate Authority Key Identifier issuer/serial does not match supplied issuer."
                )
    require_issuer_certificate_signing_authority(issuer_certificate)
    return target_time
