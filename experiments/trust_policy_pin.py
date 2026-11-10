"""Out-of-band digest pinning for caller-supplied audit trust policies.

A matching pin detects policy drift relative to a digest the caller already
possesses. It does not authenticate who issued that digest or how it was
delivered. The pin must be provisioned independently of the trust store.
"""
from __future__ import annotations

import hashlib
import json
import re

from experiments.trust_store import validate_trust_store

_PIN = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_PIN_FIELDS = {"sha256", "source_reference"}


def canonical_trust_store_bytes(store: dict) -> bytes:
    """Validate and serialise a trust store deterministically as UTF-8 JSON."""
    validate_trust_store(store)
    return json.dumps(
        store,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def trust_store_sha256(store: dict) -> str:
    """Return the SHA-256 digest of the canonical validated trust store."""
    return hashlib.sha256(canonical_trust_store_bytes(store)).hexdigest()


def verify_trust_store_pin(store: dict, pin: dict) -> dict:
    """Compare a validated trust store with a caller-supplied out-of-band pin."""
    if not isinstance(pin, dict):
        raise ValueError("pin must be an object.")
    missing = _REQUIRED_PIN_FIELDS - set(pin)
    extra = set(pin) - _REQUIRED_PIN_FIELDS
    if missing:
        raise ValueError("pin missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("pin has unsupported field(s): " + ", ".join(sorted(extra)))
    expected = pin["sha256"]
    if not isinstance(expected, str) or not _PIN.fullmatch(expected):
        raise ValueError("pin.sha256 must be 64 lowercase hexadecimal characters.")
    source = pin["source_reference"]
    if not isinstance(source, str) or not source.strip():
        raise ValueError("pin.source_reference must be a non-empty string.")

    actual = trust_store_sha256(store)
    matches = actual == expected
    return {
        "trust_policy_pin": "MATCH" if matches else "MISMATCH",
        "trust_store_sha256": actual,
        "pinned_sha256": expected,
        "pin_source_reference": source,
        "pin_source_authentication": "NOT_INDEPENDENTLY_AUTHENTICATED",
        "trust_policy_authentication": "NOT_ESTABLISHED",
        "interpretation": (
            "MATCH establishes only that the validated trust store has the same "
            "canonical SHA-256 digest as the caller-supplied pin. It does not "
            "authenticate the pin issuer, delivery channel, authority identities, "
            "or governance of the trust policy."
        ),
    }
