"""Fail-closed preflight for explicitly configured audit-verification keys.

This validates allowlist structure and eligibility only. It does not verify
signatures or establish that an authority or trust policy is genuine.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime
import re

RECORD_VERSION = "audit-trust-store/v1"
_REQUIRED_STORE_FIELDS = {"record_version", "keys"}
_REQUIRED_KEY_FIELDS = {
    "key_id", "authority_name", "algorithm", "public_key_base64",
    "purposes", "valid_from_utc", "valid_until_utc", "status",
    "trust_basis_reference",
}
_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError(f"{field} must be an ISO 8601 UTC timestamp ending in Z.")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid UTC timestamp.") from exc


def validate_trust_store(store: dict) -> dict:
    """Validate an explicit allowlist; never infer or create trusted keys."""
    if not isinstance(store, dict):
        raise ValueError("trust store must be an object.")
    missing = _REQUIRED_STORE_FIELDS - set(store)
    extra = set(store) - _REQUIRED_STORE_FIELDS
    if missing:
        raise ValueError("trust store missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("trust store has unsupported field(s): " + ", ".join(sorted(extra)))
    if store["record_version"] != RECORD_VERSION:
        raise ValueError(f"record_version must be {RECORD_VERSION}.")
    keys = store["keys"]
    if not isinstance(keys, list):
        raise ValueError("keys must be an array.")

    seen = set()
    active = 0
    for index, key in enumerate(keys):
        if not isinstance(key, dict):
            raise ValueError(f"keys[{index}] must be an object.")
        missing = _REQUIRED_KEY_FIELDS - set(key)
        extra = set(key) - _REQUIRED_KEY_FIELDS
        if missing:
            raise ValueError(f"keys[{index}] missing field(s): " + ", ".join(sorted(missing)))
        if extra:
            raise ValueError(f"keys[{index}] has unsupported field(s): " + ", ".join(sorted(extra)))
        for field in ("key_id", "authority_name", "trust_basis_reference"):
            value = key[field]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"keys[{index}].{field} must be a non-empty string.")
        if key["key_id"] in seen:
            raise ValueError(f"duplicate key_id: {key['key_id']}")
        seen.add(key["key_id"])
        if key["algorithm"] != "Ed25519":
            raise ValueError(f"keys[{index}].algorithm must be Ed25519.")
        try:
            public_key = base64.b64decode(key["public_key_base64"], validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise ValueError(f"keys[{index}].public_key_base64 must be valid base64.") from exc
        if len(public_key) != 32:
            raise ValueError(f"keys[{index}].public_key_base64 must decode to 32 bytes.")
        purposes = key["purposes"]
        if (
            not isinstance(purposes, list)
            or not purposes
            or any(not isinstance(item, str) or not item.strip() for item in purposes)
            or len(set(purposes)) != len(purposes)
        ):
            raise ValueError(f"keys[{index}].purposes must be a non-empty unique string array.")
        start = _utc(key["valid_from_utc"], f"keys[{index}].valid_from_utc")
        end = _utc(key["valid_until_utc"], f"keys[{index}].valid_until_utc")
        if end <= start:
            raise ValueError(f"keys[{index}] validity interval must be increasing.")
        if key["status"] not in {"ACTIVE", "REVOKED", "DISABLED"}:
            raise ValueError(f"keys[{index}].status must be ACTIVE, REVOKED or DISABLED.")
        if key["status"] == "ACTIVE":
            active += 1

    return {
        "trust_store_integrity": "VALID",
        "key_count": len(keys),
        "active_key_count": active,
        "signature_verification": "NOT_PERFORMED",
        "authority_authentication": "NOT_ESTABLISHED",
        "interpretation": (
            "The configured allowlist is structurally valid. This does not prove "
            "that its authority names, public keys, trust-basis references or "
            "governance are authentic or independently controlled."
        ),
    }


def resolve_eligible_key(store: dict, *, key_id: str, purpose: str, at_utc: str) -> dict:
    """Resolve policy eligibility for a key at a claimed UTC instant.

    This is a preflight, not signature verification or proof of the supplied
    instant. The caller must authenticate the trust-store source and time basis.
    """
    validate_trust_store(store)
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("key_id must be a non-empty string.")
    if not isinstance(purpose, str) or not purpose.strip():
        raise ValueError("purpose must be a non-empty string.")
    instant = _utc(at_utc, "at_utc")
    key = next((item for item in store["keys"] if item["key_id"] == key_id), None)
    if key is None:
        return {"key_eligibility": "UNKNOWN_KEY", "signature_verification": "NOT_PERFORMED"}
    start = _utc(key["valid_from_utc"], "valid_from_utc")
    end = _utc(key["valid_until_utc"], "valid_until_utc")
    if key["status"] != "ACTIVE":
        status = "KEY_NOT_ACTIVE"
    elif purpose not in key["purposes"]:
        status = "PURPOSE_NOT_ALLOWED"
    elif not start <= instant < end:
        status = "OUTSIDE_KEY_VALIDITY"
    else:
        status = "ELIGIBLE_FOR_SIGNATURE_CHECK"
    return {
        "key_eligibility": status,
        "key_id": key_id,
        "authority_name": key["authority_name"],
        "purpose": purpose,
        "public_key_base64": key["public_key_base64"] if status == "ELIGIBLE_FOR_SIGNATURE_CHECK" else None,
        "signature_verification": "NOT_PERFORMED",
        "authority_authentication": "NOT_ESTABLISHED",
        "interpretation": (
            "Eligibility means only that this caller-supplied configuration permits "
            "the key for this purpose and claimed instant. It does not verify a "
            "signature, authenticate the authority, or authenticate the instant."
        ),
    }
