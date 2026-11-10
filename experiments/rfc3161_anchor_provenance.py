"""Detached governance attestation for RFC 3161 trust-anchor provenance.

A valid signature is evaluated only relative to a caller-supplied Ed25519
trust store. This module does not authenticate that store or its governance.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime

from experiments.trust_store import resolve_eligible_key
from experiments.trust_policy_pin import verify_trust_store_pin

RECORD_VERSION = "rfc3161-tsa-anchor-provenance/v1"
PURPOSE = "RFC3161_TRUST_ANCHOR_PROVENANCE"
_DOMAIN = b"\xce\xb4ss-rfc3161-anchor-provenance/v1\n"
_FIELDS = {
    "record_version", "attestation_id", "authority_name", "anchor_sha256",
    "intended_usage", "policy_version", "sequence", "issued_at_utc",
    "expires_at_utc", "source_reference",
}
_SIGNATURE_FIELDS = {"record_version", "key_id", "signature_base64"}
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


def _time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"{field} must be an ISO 8601 UTC timestamp ending in Z.")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid UTC timestamp.") from exc


def canonical_provenance_payload(attestation: dict) -> bytes:
    """Canonical, domain-separated bytes signed by the governance key."""
    if not isinstance(attestation, dict):
        raise ValueError("attestation must be an object.")
    return _DOMAIN + json.dumps(
        attestation, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def verify_timestamp_anchor_provenance(
    anchor_pem: bytes,
    attestation: dict,
    signature_envelope: dict,
    governance_trust_store: dict,
    *,
    at_utc: str,
    minimum_sequence: int,
    trust_store_pin: dict | None = None,
) -> dict:
    """Verify a signed anchor attestation without claiming its trust root.

    minimum_sequence is operator-maintained anti-rollback state. It must come
    from outside the attestation and must not be reset from the supplied file.
    """
    if not isinstance(anchor_pem, bytes) or not anchor_pem:
        raise ValueError("anchor_pem must be non-empty bytes.")
    if b"-----BEGIN CERTIFICATE-----" not in anchor_pem:
        raise ValueError("anchor_pem must contain a PEM certificate.")
    if isinstance(minimum_sequence, bool) or not isinstance(minimum_sequence, int) or minimum_sequence < 0:
        raise ValueError("minimum_sequence must be a non-negative integer.")
    if not isinstance(attestation, dict):
        raise ValueError("attestation must be an object.")
    missing, extra = _FIELDS - set(attestation), set(attestation) - _FIELDS
    if missing:
        raise ValueError("attestation missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("attestation has unsupported field(s): " + ", ".join(sorted(extra)))
    for field in ("attestation_id", "authority_name", "source_reference"):
        if not isinstance(attestation[field], str) or not attestation[field].strip():
            raise ValueError(f"{field} must be a non-empty string.")
    if attestation["record_version"] != RECORD_VERSION:
        raise ValueError(f"record_version must be {RECORD_VERSION}.")
    if attestation["intended_usage"] != "RFC3161_TSA_TRUST_ANCHOR":
        raise ValueError("intended_usage must be RFC3161_TSA_TRUST_ANCHOR.")
    if attestation["policy_version"] != "rfc3161-tsa-anchor-policy/v1":
        raise ValueError("unsupported policy_version.")
    sequence = attestation["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ValueError("sequence must be a positive integer.")
    digest = attestation["anchor_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("anchor_sha256 must be a lowercase SHA-256 digest.")
    observed = hashlib.sha256(anchor_pem).hexdigest()
    issued = _time(attestation["issued_at_utc"], "issued_at_utc")
    expires = _time(attestation["expires_at_utc"], "expires_at_utc")
    instant = _time(at_utc, "at_utc")
    if expires <= issued:
        raise ValueError("attestation validity interval must be increasing.")

    pin_result = (
        verify_trust_store_pin(governance_trust_store, trust_store_pin)
        if trust_store_pin is not None else {"trust_policy_pin": "NOT_CHECKED"}
    )
    if trust_store_pin is not None and pin_result["trust_policy_pin"] != "MATCH":
        return {
            "provenance_verification": "GOVERNANCE_POLICY_PIN_MISMATCH",
            "attestation_signature": "NOT_PERFORMED",
            "anchor_binding": "NOT_CHECKED",
            "authority_authentication": "NOT_ESTABLISHED",
            "governance_trust_store_pin": pin_result,
        }
    if observed != digest:
        return {
            "provenance_verification": "ANCHOR_DIGEST_MISMATCH",
            "attestation_signature": "NOT_PERFORMED",
            "anchor_binding": "MISMATCH",
            "observed_anchor_sha256": observed,
            "authority_authentication": "NOT_ESTABLISHED",
            "governance_trust_store_pin": pin_result,
        }
    if sequence < minimum_sequence:
        return {
            "provenance_verification": "ROLLBACK_REJECTED",
            "attestation_signature": "NOT_PERFORMED",
            "anchor_binding": "MATCH",
            "attestation_sequence": sequence,
            "minimum_sequence": minimum_sequence,
            "authority_authentication": "NOT_ESTABLISHED",
            "governance_trust_store_pin": pin_result,
        }
    if not issued <= instant < expires:
        return {
            "provenance_verification": "ATTESTATION_OUTSIDE_VALIDITY",
            "attestation_signature": "NOT_PERFORMED",
            "anchor_binding": "MATCH",
            "authority_authentication": "NOT_ESTABLISHED",
            "governance_trust_store_pin": pin_result,
        }
    if not isinstance(signature_envelope, dict):
        raise ValueError("signature envelope must be an object.")
    missing, extra = _SIGNATURE_FIELDS - set(signature_envelope), set(signature_envelope) - _SIGNATURE_FIELDS
    if missing:
        raise ValueError("signature envelope missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("signature envelope has unsupported field(s): " + ", ".join(sorted(extra)))
    if signature_envelope["record_version"] != "rfc3161-tsa-anchor-provenance-signature/v1":
        raise ValueError("unsupported signature envelope record_version.")
    key_id = signature_envelope["key_id"]
    encoded = signature_envelope["signature_base64"]
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("signature envelope key_id must be non-empty.")
    if not isinstance(encoded, str):
        raise ValueError("signature_base64 must be a string.")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signature_base64 must be valid base64.") from exc
    if len(signature) != 64:
        raise ValueError("Ed25519 signature must decode to 64 bytes.")

    eligible = resolve_eligible_key(
        governance_trust_store, key_id=key_id, purpose=PURPOSE, at_utc=at_utc
    )
    if eligible["key_eligibility"] != "ELIGIBLE_FOR_SIGNATURE_CHECK":
        return {
            "provenance_verification": "GOVERNANCE_KEY_NOT_ELIGIBLE",
            "attestation_signature": "NOT_PERFORMED",
            "key_eligibility": eligible["key_eligibility"],
            "anchor_binding": "MATCH",
            "authority_authentication": "NOT_ESTABLISHED",
            "governance_trust_store_pin": pin_result,
        }
    if eligible["authority_name"] != attestation["authority_name"]:
        return {
            "provenance_verification": "GOVERNANCE_AUTHORITY_NAME_MISMATCH",
            "attestation_signature": "NOT_PERFORMED",
            "key_eligibility": eligible["key_eligibility"],
            "anchor_binding": "MATCH",
            "authority_authentication": "NOT_ESTABLISHED",
            "governance_trust_store_pin": pin_result,
        }
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError("Ed25519 verification requires the pinned audit-crypto dependency.") from exc
    public_key = base64.b64decode(eligible["public_key_base64"], validate=True)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, canonical_provenance_payload(attestation)
        )
        signature_status = "VALID"
    except InvalidSignature:
        signature_status = "INVALID"
    return {
        "provenance_verification": "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE" if signature_status == "VALID" else "INVALID_SIGNATURE",
        "attestation_signature": signature_status,
        "key_eligibility": eligible["key_eligibility"],
        "key_id": key_id,
        "attestation_id": attestation["attestation_id"],
        "attestation_sequence": sequence,
        "minimum_sequence": minimum_sequence,
        "anchor_binding": "MATCH",
        "intended_usage": attestation["intended_usage"],
        "authority_authentication": "NOT_ESTABLISHED",
        "governance_trust_store_pin": pin_result,
        "interpretation": (
            "A VALID signature proves only that the private key corresponding to "
            "the caller-configured eligible public key signed this attestation. "
            "It binds the exact supplied anchor bytes, intended usage, policy "
            "version, validity interval and sequence. It does not independently "
            "authenticate the governance key, trust-store source, named authority, "
            "certificate issuer, revocation status or event truth. The minimum "
            "sequence is effective only if maintained independently by the operator."
        ),
    }


def verify_rfc3161_timestamp_with_provenance(
    token_der: bytes,
    data: bytes,
    trust_anchor_pem: bytes,
    trust_anchor_pin: dict,
    attestation: dict,
    signature_envelope: dict,
    governance_trust_store: dict,
    *,
    at_utc: str,
    minimum_sequence: int,
    governance_trust_store_pin: dict | None = None,
    intermediates_pem: bytes | None = None,
    openssl_binary: str = "openssl",
    timeout_seconds: int = 10,
) -> dict:
    """Verify provenance first, then RFC 3161 token against the same anchor.

    A provenance failure prevents OpenSSL timestamp verification. Even a
    successful composite result remains relative to caller-supplied trust
    material and does not authenticate the governance root or event truth.
    """
    provenance = verify_timestamp_anchor_provenance(
        trust_anchor_pem,
        attestation,
        signature_envelope,
        governance_trust_store,
        at_utc=at_utc,
        minimum_sequence=minimum_sequence,
        trust_store_pin=governance_trust_store_pin,
    )
    if provenance["provenance_verification"] != "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE":
        return {
            "combined_verification": "PROVENANCE_NOT_VERIFIED",
            "anchor_provenance": provenance,
            "timestamp_evidence": {"timestamp_verification": "NOT_PERFORMED"},
            "governance_authentication": "NOT_ESTABLISHED",
            "event_truth": "NOT_ESTABLISHED",
        }
    from experiments.rfc3161_timestamp import verify_rfc3161_timestamp

    timestamp = verify_rfc3161_timestamp(
        token_der,
        data,
        trust_anchor_pem,
        trust_anchor_pin,
        intermediates_pem=intermediates_pem,
        openssl_binary=openssl_binary,
        timeout_seconds=timeout_seconds,
    )
    valid = timestamp["timestamp_verification"] == "VALID"
    return {
        "combined_verification": (
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE"
            if valid else "TIMESTAMP_NOT_VALID"
        ),
        "anchor_provenance": provenance,
        "timestamp_evidence": timestamp,
        "governance_authentication": "NOT_ESTABLISHED",
        "event_truth": "NOT_ESTABLISHED",
        "interpretation": (
            "The timestamp token was checked only after the exact trust-anchor "
            "bytes matched a valid provenance attestation under the caller's "
            "eligible governance key. This does not independently authenticate "
            "the governance trust root, TSA clock, certificate issuer or event."
        ),
    }
