"""Detached Ed25519 verification for canonical external audit checkpoints.

A valid signature proves that the corresponding private key signed the
canonical checkpoint payload. It does not prove the key owner's identity,
the trust-store provenance, trusted time, or the truth of the checkpoint.
"""
from __future__ import annotations

import base64
import binascii
import json

from experiments.audit_event_chain import verify_external_checkpoint
from experiments.trust_store import PURPOSE, resolve_eligible_key

_DOMAIN = b"\xce\xb4ss-audit-checkpoint-signature/v1\n"
_ENVELOPE_FIELDS = {"record_version", "key_id", "signature_base64"}
_ENVELOPE_VERSION = "audit-chain-checkpoint-signature/v1"


def canonical_checkpoint_payload(checkpoint: dict) -> bytes:
    """Return domain-separated canonical bytes for the complete checkpoint."""
    canonical = json.dumps(
        checkpoint, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _DOMAIN + canonical


def verify_signed_checkpoint(
    events: list,
    checkpoint: dict,
    signature_envelope: dict,
    trust_store: dict,
    *,
    at_utc: str,
) -> dict:
    """Verify checkpoint binding and detached signature against caller policy."""
    checkpoint_result = verify_external_checkpoint(events, checkpoint)
    if not isinstance(signature_envelope, dict):
        raise ValueError("signature envelope must be an object.")
    missing = _ENVELOPE_FIELDS - set(signature_envelope)
    extra = set(signature_envelope) - _ENVELOPE_FIELDS
    if missing:
        raise ValueError("signature envelope missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("signature envelope has unsupported field(s): " + ", ".join(sorted(extra)))
    if signature_envelope["record_version"] != _ENVELOPE_VERSION:
        raise ValueError(f"signature envelope record_version must be {_ENVELOPE_VERSION}.")
    key_id = signature_envelope["key_id"]
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("signature envelope key_id must be a non-empty string.")
    if not isinstance(signature_envelope["signature_base64"], str):
        raise ValueError("signature_base64 must be a string.")
    try:
        signature = base64.b64decode(signature_envelope["signature_base64"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signature_base64 must be valid base64.") from exc
    if len(signature) != 64:
        raise ValueError("Ed25519 signature must decode to 64 bytes.")

    eligible = resolve_eligible_key(
        trust_store, key_id=key_id, purpose=PURPOSE, at_utc=at_utc
    )
    if eligible["key_eligibility"] != "ELIGIBLE_FOR_SIGNATURE_CHECK":
        return {
            "signed_checkpoint_verification": "NOT_ELIGIBLE",
            "signature_verification": "NOT_PERFORMED",
            "key_eligibility": eligible["key_eligibility"],
            "checkpoint": checkpoint_result,
            "authority_authentication": "NOT_ESTABLISHED",
            "timestamp_authentication": "NOT_ESTABLISHED",
        }

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 verification requires the pinned audit-crypto dependency."
        ) from exc

    public_key = base64.b64decode(eligible["public_key_base64"], validate=True)
    verifier = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        verifier.verify(signature, canonical_checkpoint_payload(checkpoint))
        signature_status = "VALID"
    except InvalidSignature:
        signature_status = "INVALID"

    checkpoint_matches = (
        checkpoint_result["checkpoint_binding"] == "MATCH"
        and checkpoint_result["checkpoint_time_order"] == "NOT_BEFORE_EVENT"
    )
    overall = (
        "MATCH"
        if signature_status == "VALID" and checkpoint_matches
        else "MISMATCH"
    )
    return {
        "signed_checkpoint_verification": overall,
        "signature_verification": signature_status,
        "key_eligibility": eligible["key_eligibility"],
        "key_id": key_id,
        "checkpoint": checkpoint_result,
        "authority_authentication": "NOT_ESTABLISHED",
        "timestamp_authentication": "NOT_ESTABLISHED",
        "interpretation": (
            "A VALID signature proves only that the private key corresponding to "
            "the configured public key signed these canonical checkpoint bytes. "
            "It does not independently authenticate the key owner, trust-store "
            "source, timestamp, anchor storage or event truth."
        ),
    }
