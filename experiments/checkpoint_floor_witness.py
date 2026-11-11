"""Signed external checkpoint-floor witness contract and receipt verification.

This is an adapter boundary, not a storage service. A conforming provider must
perform atomic compare-and-advance in a trust domain independent of local
checkpoint storage. Distinct failure-domain labels do not prove independence.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import Protocol

from experiments.audit_event_chain import _timestamp
from experiments.trust_store import resolve_eligible_key
from experiments.trust_policy_pin import verify_trust_store_pin

WITNESS_PURPOSE = "CHECKPOINT_FLOOR_WITNESS"
_RECEIPT_VERSION = "audit-checkpoint-floor-witness/v1"
_SIGNATURE_VERSION = "audit-checkpoint-floor-witness-signature/v1"
_DOMAIN = b"\xce\xb4ss-checkpoint-floor-witness/v1\n"
_RECEIPT_FIELDS = {
    "record_version", "witness_id", "provider_id", "failure_domain_id",
    "authority_name", "witness_sequence", "minimum_checkpoint_sequence",
    "previous_receipt_sha256", "issued_at_utc", "expires_at_utc",
}
_SIGNATURE_FIELDS = {"record_version", "key_id", "signature_base64"}


class CheckpointFloorWitness(Protocol):
    """Provider contract: atomic compare-and-advance outside local storage.

    read_latest returns (receipt, signature_envelope). advance_floor must
    atomically compare expected_witness_sequence, monotonically advance the
    floor, and be idempotent for a repeated idempotency_key. Both return the
    exact signed receipt tuple. The operator must pin the provider identity,
    failure domain and minimum witness sequence independently.
    """

    def read_latest(self) -> tuple[dict, dict]:
        """Return the latest signed witness receipt and signature envelope."""
        ...

    def advance_floor(
        self, *, expected_witness_sequence: int,
        minimum_checkpoint_sequence: int, idempotency_key: str,
    ) -> tuple[dict, dict]:
        """Atomically compare-and-advance and return the signed receipt tuple."""
        ...


def canonical_witness_payload(receipt: dict) -> bytes:
    """Return domain-separated canonical bytes for the complete receipt."""
    canonical = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return _DOMAIN + canonical


def _non_empty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string.")
    return value


def _integer(value: object, field: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{field} must be a {qualifier} integer.")
    return value


class CheckpointFloorWitnessEvidenceError(ValueError):
    """Receipt or signature-envelope evidence is structurally invalid."""


def _validate_checkpoint_floor_witness_evidence(
    receipt: object, signature_envelope: object,
) -> tuple[int, int, str, object, object, bytes, str]:
    """Validate untrusted receipt/envelope shape without inspecting operator policy."""
    try:
        if not isinstance(receipt, dict):
            raise ValueError("receipt must be an object.")
        missing, extra = _RECEIPT_FIELDS - set(receipt), set(receipt) - _RECEIPT_FIELDS
        if missing:
            raise ValueError("receipt missing field(s): " + ", ".join(sorted(missing)))
        if extra:
            raise ValueError("receipt has unsupported field(s): " + ", ".join(sorted(extra)))
        if receipt["record_version"] != _RECEIPT_VERSION:
            raise ValueError(f"receipt record_version must be {_RECEIPT_VERSION}.")
        for field in ("witness_id", "provider_id", "failure_domain_id", "authority_name"):
            _non_empty(receipt[field], field)
        sequence = _integer(receipt["witness_sequence"], "witness_sequence", positive=True)
        floor = _integer(receipt["minimum_checkpoint_sequence"], "minimum_checkpoint_sequence")
        previous = receipt["previous_receipt_sha256"]
        if not isinstance(previous, str) or not re.fullmatch(r"[0-9a-f]{64}", previous):
            raise ValueError("previous_receipt_sha256 must be a lowercase SHA-256 digest.")
        issued = _timestamp(receipt["issued_at_utc"], "receipt.issued_at_utc")
        expires = _timestamp(receipt["expires_at_utc"], "receipt.expires_at_utc")
        if expires <= issued:
            raise ValueError("receipt validity interval must be increasing.")

        if not isinstance(signature_envelope, dict):
            raise ValueError("signature_envelope must be an object.")
        missing, extra = _SIGNATURE_FIELDS - set(signature_envelope), set(signature_envelope) - _SIGNATURE_FIELDS
        if missing:
            raise ValueError("signature_envelope missing field(s): " + ", ".join(sorted(missing)))
        if extra:
            raise ValueError("signature_envelope has unsupported field(s): " + ", ".join(sorted(extra)))
        if signature_envelope["record_version"] != _SIGNATURE_VERSION:
            raise ValueError(f"signature envelope record_version must be {_SIGNATURE_VERSION}.")
        key_id = _non_empty(signature_envelope["key_id"], "signature_envelope.key_id")
        encoded = signature_envelope["signature_base64"]
        if not isinstance(encoded, str):
            raise ValueError("signature_base64 must be a string.")
        try:
            signature = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("signature_base64 must be valid base64.") from exc
        if len(signature) != 64:
            raise ValueError("Ed25519 signature must decode to 64 bytes.")
        return sequence, floor, previous, issued, expires, signature, key_id
    except ValueError as exc:
        raise CheckpointFloorWitnessEvidenceError(str(exc)) from exc


def verify_checkpoint_floor_witness_receipt(
    receipt: dict, signature_envelope: dict, trust_store: dict, *,
    at_utc: str, expected_witness_id: str, expected_provider_id: str,
    expected_failure_domain_id: str, local_storage_domain_id: str,
    minimum_witness_sequence: int, minimum_checkpoint_sequence: int,
    trust_store_pin: dict | None = None,
) -> dict:
    """Verify a signed receipt against caller-pinned identity and floor policy.

    Success is relative to supplied governance keys and operator configuration.
    A distinct failure-domain identifier is a declaration only; operational
    separation must be established independently by the deployment operator.
    """
    sequence, floor, previous, issued, expires, signature, key_id = (
        _validate_checkpoint_floor_witness_evidence(receipt, signature_envelope)
    )

    for field, expected in (
        ("witness_id", expected_witness_id),
        ("provider_id", expected_provider_id),
        ("failure_domain_id", expected_failure_domain_id),
    ):
        if receipt[field] != _non_empty(expected, "expected_" + field):
            return {
                "witness_verification": "IDENTITY_MISMATCH",
                "signature_verification": "NOT_PERFORMED",
                "authority_authentication": "NOT_ESTABLISHED",
            }

    local_domain = _non_empty(local_storage_domain_id, "local_storage_domain_id")
    if receipt["failure_domain_id"] == local_domain:
        return {
            "witness_verification": "SAME_FAILURE_DOMAIN",
            "signature_verification": "NOT_PERFORMED",
            "failure_domain_separation": "NOT_SEPARATE",
            "authority_authentication": "NOT_ESTABLISHED",
        }

    minimum_witness_sequence = _integer(minimum_witness_sequence, "minimum_witness_sequence")
    minimum_checkpoint_sequence = _integer(
        minimum_checkpoint_sequence, "minimum_checkpoint_sequence"
    )
    instant = _timestamp(at_utc, "at_utc")
    if not issued <= instant < expires:
        return {
            "witness_verification": "RECEIPT_OUTSIDE_VALIDITY",
            "signature_verification": "NOT_PERFORMED",
            "authority_authentication": "NOT_ESTABLISHED",
        }
    if sequence < minimum_witness_sequence or floor < minimum_checkpoint_sequence:
        return {
            "witness_verification": "ROLLBACK_REJECTED",
            "signature_verification": "NOT_PERFORMED",
            "witness_sequence": sequence,
            "minimum_witness_sequence": minimum_witness_sequence,
            "witness_checkpoint_floor": floor,
            "minimum_checkpoint_sequence": minimum_checkpoint_sequence,
            "authority_authentication": "NOT_ESTABLISHED",
        }

    pin = (
        verify_trust_store_pin(trust_store, trust_store_pin)
        if trust_store_pin is not None else {"trust_policy_pin": "NOT_CHECKED"}
    )
    if trust_store_pin is not None and pin["trust_policy_pin"] != "MATCH":
        return {
            "witness_verification": "GOVERNANCE_POLICY_PIN_MISMATCH",
            "signature_verification": "NOT_PERFORMED",
            "trust_policy_pin": pin,
            "authority_authentication": "NOT_ESTABLISHED",
        }
    eligible = resolve_eligible_key(
        trust_store, key_id=key_id, purpose=WITNESS_PURPOSE, at_utc=at_utc
    )
    if eligible["key_eligibility"] != "ELIGIBLE_FOR_SIGNATURE_CHECK":
        return {
            "witness_verification": "GOVERNANCE_KEY_NOT_ELIGIBLE",
            "signature_verification": "NOT_PERFORMED",
            "key_eligibility": eligible["key_eligibility"],
            "authority_authentication": "NOT_ESTABLISHED",
            "trust_policy_pin": pin,
        }
    if eligible["authority_name"] != receipt["authority_name"]:
        return {
            "witness_verification": "GOVERNANCE_AUTHORITY_NAME_MISMATCH",
            "signature_verification": "NOT_PERFORMED",
            "key_eligibility": eligible["key_eligibility"],
            "authority_authentication": "NOT_ESTABLISHED",
            "trust_policy_pin": pin,
        }
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 verification requires the pinned audit-crypto dependency."
        ) from exc
    public = base64.b64decode(eligible["public_key_base64"], validate=True)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, canonical_witness_payload(receipt)
        )
        signature_status = "VALID"
    except InvalidSignature:
        signature_status = "INVALID"
    return {
        "witness_verification": (
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_AND_DOMAIN_CONFIGURATION"
            if signature_status == "VALID" else "INVALID_SIGNATURE"
        ),
        "signature_verification": signature_status,
        "witness_id": receipt["witness_id"],
        "provider_id": receipt["provider_id"],
        "failure_domain_id": receipt["failure_domain_id"],
        "witness_sequence": sequence,
        "minimum_witness_sequence": minimum_witness_sequence,
        "minimum_checkpoint_sequence": floor,
        "required_checkpoint_sequence": minimum_checkpoint_sequence,
        "previous_receipt_sha256": previous,
        "failure_domain_separation": "DECLARED_DISTINCT_NOT_INDEPENDENTLY_PROVEN",
        "authority_authentication": "NOT_ESTABLISHED",
        "trust_policy_pin": pin,
        "interpretation": (
            "The receipt signature and configured identity, sequence and floor "
            "checks were evaluated relative to caller-supplied trust material. "
            "A distinct failure-domain identifier is a declaration, not proof "
            "of separate ownership, infrastructure, administration, backup or "
            "recovery. Maintain minimum_witness_sequence outside the local "
            "ledger and independently verify provider separation."
        ),
    }



class CheckpointFloorWitnessAdvanceUncertain(RuntimeError):
    """Provider advance outcome is unknown or its returned receipt is unusable."""

    def __init__(self, message, *, idempotency_key, minimum_checkpoint_sequence,
                 receipt=None, signature_envelope=None):
        super().__init__(message)
        self.idempotency_key = idempotency_key
        self.minimum_checkpoint_sequence = minimum_checkpoint_sequence
        self.receipt = receipt
        self.signature_envelope = signature_envelope


class CheckpointFloorWitnessLocalCommitUncertain(RuntimeError):
    """The witness advanced but the matching local floor append did not confirm."""

    def __init__(self, message, *, receipt, signature_envelope, idempotency_key,
                 minimum_checkpoint_sequence):
        super().__init__(message)
        self.receipt = receipt
        self.signature_envelope = signature_envelope
        self.idempotency_key = idempotency_key
        self.minimum_checkpoint_sequence = minimum_checkpoint_sequence


def advance_checkpoint_floor_with_witness(
    witness: CheckpointFloorWitness,
    ledger_path,
    minimum_checkpoint_sequence: int,
    recorded_at_utc: str,
    trust_store: dict,
    *,
    at_utc: str,
    expected_witness_id: str,
    expected_provider_id: str,
    expected_failure_domain_id: str,
    local_storage_domain_id: str,
    minimum_witness_sequence: int,
    operator_minimum_checkpoint_sequence: int,
    idempotency_key: str,
    trust_store_pin: dict | None = None,
) -> dict:
    """Advance the external witness first, then bring the local ledger up to it.

    If the local append fails after witness advancement, raise
    CheckpointFloorWitnessLocalCommitUncertain with the accepted signed receipt.
    Retrying with the same idempotency key reads the provider's latest receipt
    and retries local convergence; it never attempts to lower the witness.
    """
    requested_floor = _integer(
        minimum_checkpoint_sequence, "minimum_checkpoint_sequence"
    )
    operator_floor = _integer(
        operator_minimum_checkpoint_sequence, "operator_minimum_checkpoint_sequence"
    )
    key = _non_empty(idempotency_key, "idempotency_key")
    if requested_floor < operator_floor:
        raise ValueError(
            "requested checkpoint floor is below the operator minimum; refusing regression."
        )

    from experiments.checkpoint_floor_ledger import (
        append_checkpoint_floor, checkpoint_floor_value,
    )

    try:
        local_floor = checkpoint_floor_value(ledger_path)
    except FileNotFoundError:
        if not Path(ledger_path).parent.is_dir():
            raise
        local_floor = None

    current_receipt, current_signature = witness.read_latest()
    current_result = verify_checkpoint_floor_witness_receipt(
        current_receipt, current_signature, trust_store,
        at_utc=at_utc,
        expected_witness_id=expected_witness_id,
        expected_provider_id=expected_provider_id,
        expected_failure_domain_id=expected_failure_domain_id,
        local_storage_domain_id=local_storage_domain_id,
        minimum_witness_sequence=minimum_witness_sequence,
        minimum_checkpoint_sequence=operator_floor,
        trust_store_pin=trust_store_pin,
    )
    if current_result["witness_verification"] != (
        "VALID_RELATIVE_TO_CALLER_GOVERNANCE_AND_DOMAIN_CONFIGURATION"
    ):
        raise ValueError(
            "current external witness receipt is not acceptable: "
            + current_result["witness_verification"]
        )

    target_floor = max(
        requested_floor,
        operator_floor,
        current_receipt["minimum_checkpoint_sequence"],
        local_floor if local_floor is not None else 0,
    )
    accepted_receipt, accepted_signature = current_receipt, current_signature
    if target_floor > current_receipt["minimum_checkpoint_sequence"]:
        try:
            accepted_receipt, accepted_signature = witness.advance_floor(
                expected_witness_sequence=current_receipt["witness_sequence"],
                minimum_checkpoint_sequence=target_floor,
                idempotency_key=key,
            )
        except Exception as exc:
            raise CheckpointFloorWitnessAdvanceUncertain(
                "provider advance outcome is unknown; retry by reading the witness "
                "and using the same idempotency key",
                idempotency_key=key,
                minimum_checkpoint_sequence=target_floor,
            ) from exc
        try:
            advanced_result = verify_checkpoint_floor_witness_receipt(
                accepted_receipt, accepted_signature, trust_store,
                at_utc=at_utc,
                expected_witness_id=expected_witness_id,
                expected_provider_id=expected_provider_id,
                expected_failure_domain_id=expected_failure_domain_id,
                local_storage_domain_id=local_storage_domain_id,
                minimum_witness_sequence=current_receipt["witness_sequence"] + 1,
                minimum_checkpoint_sequence=target_floor,
                trust_store_pin=trust_store_pin,
            )
        except Exception as exc:
            raise CheckpointFloorWitnessAdvanceUncertain(
                "provider may have advanced but its returned receipt could not be "
                "verified; retry by reading the witness and using the same idempotency key",
                idempotency_key=key,
                minimum_checkpoint_sequence=target_floor,
                receipt=accepted_receipt,
                signature_envelope=accepted_signature,
            ) from exc
        if advanced_result["witness_verification"] != (
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_AND_DOMAIN_CONFIGURATION"
        ):
            raise CheckpointFloorWitnessAdvanceUncertain(
                "provider may have advanced but its returned receipt was rejected: "
                + advanced_result["witness_verification"],
                idempotency_key=key,
                minimum_checkpoint_sequence=target_floor,
                receipt=accepted_receipt,
                signature_envelope=accepted_signature,
            )
        current_result = advanced_result
        # A concurrent provider advance may return a floor higher than the
        # requested value. The local ledger must converge to the signed value.
        target_floor = max(
            target_floor, accepted_receipt["minimum_checkpoint_sequence"]
        )

    try:
        local_append = append_checkpoint_floor(
            ledger_path, target_floor, recorded_at_utc
        )
    except Exception as exc:
        raise CheckpointFloorWitnessLocalCommitUncertain(
            "external witness floor is retained but local ledger convergence "
            "did not confirm; retry with the same idempotency key and never "
            "lower the witness",
            receipt=accepted_receipt,
            signature_envelope=accepted_signature,
            idempotency_key=key,
            minimum_checkpoint_sequence=target_floor,
        ) from exc

    return {
        "coordination": "WITNESS_VERIFIED_LOCAL_LEDGER_CONVERGED",
        "minimum_checkpoint_sequence": target_floor,
        "witness": current_result,
        "local_ledger_append": local_append,
        "idempotency_key": key,
        "authority_authentication": "NOT_ESTABLISHED",
        "failure_domain_separation": "DECLARED_DISTINCT_NOT_INDEPENDENTLY_PROVEN",
    }


def classify_checkpoint_recovery_with_witness(
    events: list,
    checkpoint: dict | None,
    acceptance_receipt: dict | None,
    witness_receipt: dict,
    witness_signature_envelope: dict,
    trust_store: dict,
    floor_ledger_path,
    *,
    at_utc: str,
    expected_witness_id: str,
    expected_provider_id: str,
    expected_failure_domain_id: str,
    local_storage_domain_id: str,
    minimum_witness_sequence: int,
    operator_minimum_checkpoint_sequence: int,
    trust_store_pin: dict | None = None,
) -> dict:
    """Classify recovery only when signed witness and local floors agree.

    Invalid witness evidence returns WITNESS_NOT_VERIFIED. Missing or corrupt
    local history propagates an error. A witness/local floor mismatch returns
    an explicit divergence state rather than silently choosing either source.
    """
    try:
        witness_result = verify_checkpoint_floor_witness_receipt(
            witness_receipt, witness_signature_envelope, trust_store,
            at_utc=at_utc,
            expected_witness_id=expected_witness_id,
            expected_provider_id=expected_provider_id,
            expected_failure_domain_id=expected_failure_domain_id,
            local_storage_domain_id=local_storage_domain_id,
            minimum_witness_sequence=minimum_witness_sequence,
            minimum_checkpoint_sequence=operator_minimum_checkpoint_sequence,
            trust_store_pin=trust_store_pin,
        )
    except CheckpointFloorWitnessEvidenceError as exc:
        return {
            "recovery_status": "WITNESS_NOT_VERIFIED",
            "witness_verification": {
                "witness_verification": "MALFORMED_WITNESS_EVIDENCE",
                "signature_verification": "NOT_PERFORMED",
                "evidence_error": str(exc),
                "authority_authentication": "NOT_ESTABLISHED",
            },
            "rollback_floor": "NOT_TRUSTED",
            "acceptance_authentication": "NOT_VERIFIED",
            "authority_authentication": "NOT_ESTABLISHED",
        }
    valid_status = "VALID_RELATIVE_TO_CALLER_GOVERNANCE_AND_DOMAIN_CONFIGURATION"
    if witness_result["witness_verification"] != valid_status:
        return {
            "recovery_status": "WITNESS_NOT_VERIFIED",
            "witness_verification": witness_result,
            "rollback_floor": "NOT_TRUSTED",
            "acceptance_authentication": "NOT_VERIFIED",
            "authority_authentication": "NOT_ESTABLISHED",
        }

    from experiments.checkpoint_floor_ledger import load_checkpoint_floor_ledger

    entries = load_checkpoint_floor_ledger(floor_ledger_path)
    local_latest = entries[-1]
    local_floor = local_latest["minimum_checkpoint_sequence"]
    witness_floor = witness_receipt["minimum_checkpoint_sequence"]
    if local_floor != witness_floor:
        divergence = (
            "WITNESS_AHEAD_OF_LOCAL_LEDGER"
            if witness_floor > local_floor
            else "LOCAL_LEDGER_AHEAD_OF_WITNESS"
        )
        return {
            "recovery_status": "WITNESS_LOCAL_LEDGER_DIVERGENCE",
            "rollback_floor": divergence,
            "local_ledger_floor": local_floor,
            "local_ledger_revision": local_latest["floor_revision"],
            "witness_floor": witness_floor,
            "witness_sequence": witness_receipt["witness_sequence"],
            "witness_verification": witness_result,
            "acceptance_authentication": "NOT_VERIFIED",
            "authority_authentication": "NOT_ESTABLISHED",
            "interpretation": (
                "The authenticated-relative-to-caller witness and local ledger "
                "do not retain the same floor. Do not classify or accept recovery "
                "from either source alone; reconcile without lowering either floor."
            ),
        }

    from experiments.checkpoint_recovery import classify_checkpoint_recovery

    result = classify_checkpoint_recovery(
        events, checkpoint, acceptance_receipt, minimum_sequence=witness_floor
    )
    result["rollback_floor_source"] = (
        "EXTERNAL_WITNESS_MATCHED_TO_LOCAL_LEDGER_RELATIVE_TO_CALLER_CONFIGURATION"
    )
    result["local_ledger_revision"] = local_latest["floor_revision"]
    result["local_ledger_entry_sha256"] = local_latest["entry_sha256"]
    result["witness_verification"] = witness_result
    result["witness_id"] = witness_receipt["witness_id"]
    result["witness_provider_id"] = witness_receipt["provider_id"]
    result["witness_sequence"] = witness_receipt["witness_sequence"]
    result["witness_failure_domain_id"] = witness_receipt["failure_domain_id"]
    result["failure_domain_separation"] = (
        "DECLARED_DISTINCT_NOT_INDEPENDENTLY_PROVEN"
    )
    result["authority_authentication"] = "NOT_ESTABLISHED"
    return result
