"""Signed, anti-replay recovery-anchor verification and recovery gate.

A VALID result is relative to caller-supplied trust material and time. It does
not authenticate the trust root, the named authority, or the anchor's claimed
operational failure-domain independence.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime

from experiments.operator_pin_store import validate_independent_recovery_anchor
from experiments.trust_store import resolve_eligible_key
from experiments.trust_policy_pin import verify_trust_store_pin

RECORD_VERSION = "audit-independent-recovery-anchor-attestation/v1"
SIGNATURE_VERSION = "audit-independent-recovery-anchor-signature/v1"
PURPOSE = "INDEPENDENT_RECOVERY_ANCHOR"
_DOMAIN = b"\xce\xb4ss-independent-recovery-anchor/v1\n"
_FIELDS = {"record_version", "attestation_id", "authority_name", "sequence",
           "issued_at_utc", "expires_at_utc", "anchor"}
_SIGNATURE_FIELDS = {"record_version", "key_id", "signature_base64"}
_TIME = re.compile(r"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?Z$")


def _time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"{field} must be an ISO 8601 UTC timestamp ending in Z.")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid UTC timestamp.") from exc


def canonical_recovery_anchor_payload(attestation: dict) -> bytes:
    """Return canonical, domain-separated bytes for the exact attestation."""
    if not isinstance(attestation, dict):
        raise ValueError("attestation must be an object.")
    return _DOMAIN + json.dumps(
        attestation, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def verify_independent_recovery_anchor(
    attestation: dict,
    signature_envelope: dict,
    governance_trust_store: dict,
    *,
    at_utc: str,
    minimum_anchor_sequence: int,
    trust_store_pin: dict | None = None,
) -> dict:
    """Verify signature, purpose, validity and externally retained anti-replay floor.

    minimum_anchor_sequence must be maintained outside the attestation and
    outside the operator-pin ledger's rollback/backup failure domain.
    """
    if not isinstance(minimum_anchor_sequence, int) or isinstance(minimum_anchor_sequence, bool) or minimum_anchor_sequence < 1:
        raise ValueError("minimum_anchor_sequence must be a positive integer.")
    if not isinstance(attestation, dict):
        raise ValueError("attestation must be an object.")
    missing, extra = _FIELDS - set(attestation), set(attestation) - _FIELDS
    if missing:
        raise ValueError("attestation missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("attestation has unsupported field(s): " + ", ".join(sorted(extra)))
    if attestation["record_version"] != RECORD_VERSION:
        raise ValueError(f"record_version must be {RECORD_VERSION}.")
    for field in ("attestation_id", "authority_name"):
        if not isinstance(attestation[field], str) or not attestation[field].strip():
            raise ValueError(f"{field} must be a non-empty string.")
    sequence = attestation["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ValueError("sequence must be a positive integer.")
    anchor = validate_independent_recovery_anchor(attestation["anchor"])
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
        return {"anchor_verification": "GOVERNANCE_POLICY_PIN_MISMATCH",
                "attestation_signature": "NOT_PERFORMED",
                "authority_authentication": "NOT_ESTABLISHED",
                "governance_trust_store_pin": pin_result}
    if sequence < minimum_anchor_sequence:
        return {"anchor_verification": "ROLLBACK_REJECTED",
                "attestation_signature": "NOT_PERFORMED",
                "attestation_sequence": sequence,
                "minimum_anchor_sequence": minimum_anchor_sequence,
                "authority_authentication": "NOT_ESTABLISHED",
                "governance_trust_store_pin": pin_result}
    if not issued <= instant < expires:
        return {"anchor_verification": "ATTESTATION_OUTSIDE_VALIDITY",
                "attestation_signature": "NOT_PERFORMED",
                "authority_authentication": "NOT_ESTABLISHED",
                "governance_trust_store_pin": pin_result}

    if not isinstance(signature_envelope, dict):
        raise ValueError("signature envelope must be an object.")
    missing, extra = _SIGNATURE_FIELDS - set(signature_envelope), set(signature_envelope) - _SIGNATURE_FIELDS
    if missing:
        raise ValueError("signature envelope missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("signature envelope has unsupported field(s): " + ", ".join(sorted(extra)))
    if signature_envelope["record_version"] != SIGNATURE_VERSION:
        raise ValueError(f"signature envelope record_version must be {SIGNATURE_VERSION}.")
    key_id, encoded = signature_envelope["key_id"], signature_envelope["signature_base64"]
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
        return {"anchor_verification": "GOVERNANCE_KEY_NOT_ELIGIBLE",
                "attestation_signature": "NOT_PERFORMED",
                "key_eligibility": eligible["key_eligibility"],
                "authority_authentication": "NOT_ESTABLISHED",
                "governance_trust_store_pin": pin_result}
    if eligible["authority_name"] != attestation["authority_name"]:
        return {"anchor_verification": "GOVERNANCE_AUTHORITY_NAME_MISMATCH",
                "attestation_signature": "NOT_PERFORMED",
                "key_eligibility": eligible["key_eligibility"],
                "authority_authentication": "NOT_ESTABLISHED",
                "governance_trust_store_pin": pin_result}
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError("Ed25519 verification requires the pinned audit-crypto dependency.") from exc
    public_key = base64.b64decode(eligible["public_key_base64"], validate=True)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, canonical_recovery_anchor_payload(attestation)
        )
        status = "VALID"
    except InvalidSignature:
        status = "INVALID"
    return {
        "anchor_verification": (
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE" if status == "VALID"
            else "INVALID_SIGNATURE"
        ),
        "attestation_signature": status,
        "key_eligibility": eligible["key_eligibility"],
        "key_id": key_id,
        "attestation_id": attestation["attestation_id"],
        "attestation_sequence": sequence,
        "minimum_anchor_sequence": minimum_anchor_sequence,
        "independent_recovery_anchor": anchor,
        "authority_authentication": "NOT_ESTABLISHED",
        "governance_trust_store_pin": pin_result,
        "interpretation": (
            "A VALID signature binds the exact recovery-anchor fields and validity "
            "interval to the caller-configured eligible Ed25519 key. It does not "
            "authenticate that trust root, the named authority, the claimed source "
            "independence, the supplied clock, or event truth. The anti-replay floor "
            "is effective only when retained independently by the operator."
        ),
    }


def classify_checkpoint_recovery_with_signed_anchor(
    *args,
    recovery_anchor_attestation: dict,
    recovery_anchor_signature_envelope: dict,
    recovery_anchor_trust_store: dict,
    at_utc: str,
    minimum_anchor_sequence: int,
    recovery_anchor_trust_store_pin: dict | None = None,
    **kwargs,
) -> dict:
    """Verify the signed anchor before entering the existing recovery gate.

    The positional/keyword arguments otherwise match
    classify_checkpoint_recovery_with_operator_pins. A caller-supplied
    independent_recovery_anchor is forbidden; only the verified embedded anchor
    is forwarded.
    """
    if "independent_recovery_anchor" in kwargs:
        raise ValueError("do not supply independent_recovery_anchor; it is bound by the signed attestation.")
    verified = verify_independent_recovery_anchor(
        recovery_anchor_attestation,
        recovery_anchor_signature_envelope,
        recovery_anchor_trust_store,
        at_utc=at_utc,
        minimum_anchor_sequence=minimum_anchor_sequence,
        trust_store_pin=recovery_anchor_trust_store_pin,
    )
    if verified["anchor_verification"] != "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE":
        return {
            "recovery_status": "RECOVERY_ANCHOR_NOT_VERIFIED",
            "recovery_anchor": verified,
            "recovery_classification": "NOT_PERFORMED",
        }
    from experiments.operator_pin_store import classify_checkpoint_recovery_with_operator_pins
    result = classify_checkpoint_recovery_with_operator_pins(
        *args, independent_recovery_anchor=verified["independent_recovery_anchor"],
        **kwargs,
    )
    result = dict(result)
    result["recovery_anchor_signature_verification"] = verified
    result["operator_pin_rollback_guard"] = "SIGNED_INDEPENDENT_ANCHOR_MINIMA_CHECKED"
    return result
