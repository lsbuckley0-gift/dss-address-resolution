"""Crash-recovery classification for externally retained audit checkpoints.

This module compares a checkpoint payload with a separately retained acceptance
receipt. It does not perform durable writes, provide atomicity, authenticate the
receipt issuer, or establish the trustworthiness of either storage location.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re

from experiments.audit_event_chain import _timestamp, verify_external_checkpoint

_RECEIPT_FIELDS = {
    "record_version",
    "checkpoint_sequence",
    "checkpoint_sha256",
    "accepted_at_utc",
    "receipt_reference",
}
_RECEIPT_VERSION = "audit-checkpoint-acceptance/v1"


def _canonical_checkpoint_sha256(checkpoint: dict) -> str:
    canonical = json.dumps(
        checkpoint, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_receipt(receipt: dict) -> None:
    if not isinstance(receipt, dict):
        raise ValueError("acceptance_receipt must be an object.")
    missing = _RECEIPT_FIELDS - set(receipt)
    extra = set(receipt) - _RECEIPT_FIELDS
    if missing:
        raise ValueError(
            "acceptance_receipt missing field(s): " + ", ".join(sorted(missing))
        )
    if extra:
        raise ValueError(
            "acceptance_receipt has unsupported field(s): " + ", ".join(sorted(extra))
        )
    if receipt["record_version"] != _RECEIPT_VERSION:
        raise ValueError("acceptance_receipt has an unsupported record_version.")
    sequence = receipt["checkpoint_sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ValueError("acceptance_receipt checkpoint_sequence must be a non-negative integer.")
    digest = receipt["checkpoint_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("acceptance_receipt checkpoint_sha256 must be a lowercase SHA-256 digest.")
    for field in ("receipt_reference",):
        value = receipt[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"acceptance_receipt {field} must be non-empty.")
    _timestamp(receipt["accepted_at_utc"], "acceptance_receipt.accepted_at_utc")


def classify_checkpoint_recovery(
    events: list,
    checkpoint: dict | None,
    acceptance_receipt: dict | None,
    *,
    minimum_sequence: int | None = None,
) -> dict:
    """Classify retained checkpoint/receipt state after an interrupted write.

    A CONSISTENT result means only that the supplied objects agree with one
    another and with the supplied event chain. It is not authenticated
    acceptance and does not prove that storage writes were atomic or durable.
    """
    if minimum_sequence is not None and (
        isinstance(minimum_sequence, bool)
        or not isinstance(minimum_sequence, int)
        or minimum_sequence < 0
    ):
        raise ValueError("minimum_sequence must be a non-negative integer when supplied.")

    if checkpoint is None and acceptance_receipt is None:
        return {
            "recovery_status": "NO_RETAINED_STATE",
            "checkpoint_binding": "NOT_CHECKED",
            "rollback_floor": "NOT_COMPARABLE",
            "acceptance_authentication": "NOT_VERIFIED",
            "storage_atomicity": "NOT_VERIFIED",
            "interpretation": (
                "Neither checkpoint payload nor acceptance receipt was supplied. "
                "The verifier cannot distinguish first use from loss of retained state."
            ),
        }

    if checkpoint is None:
        _validate_receipt(acceptance_receipt)
        floor_status = "NOT_SUPPLIED"
        if minimum_sequence is not None:
            floor_status = (
                "MEETS_FLOOR"
                if acceptance_receipt["checkpoint_sequence"] >= minimum_sequence
                else "BELOW_FLOOR"
            )
        return {
            "recovery_status": "RECEIPT_WITHOUT_PAYLOAD",
            "checkpoint_binding": "MISSING_PAYLOAD",
            "receipt_sequence": acceptance_receipt["checkpoint_sequence"],
            "rollback_floor": floor_status,
            "acceptance_authentication": "NOT_VERIFIED",
            "storage_atomicity": "NOT_VERIFIED",
            "interpretation": (
                "An acceptance receipt is present but its checkpoint payload is absent. "
                "Do not reconstruct or accept the missing payload from the receipt alone."
            ),
        }

    if acceptance_receipt is None:
        checkpoint_result = verify_external_checkpoint(events, checkpoint)
        floor_status = "NOT_SUPPLIED"
        if minimum_sequence is not None:
            floor_status = (
                "MEETS_FLOOR"
                if checkpoint["checkpoint_sequence"] >= minimum_sequence
                else "BELOW_FLOOR"
            )
        binding_valid = (
            checkpoint_result["checkpoint_binding"] == "MATCH"
            and checkpoint_result["checkpoint_time_order"] == "NOT_BEFORE_EVENT"
        )
        recovery_status = (
            "PREPARED_NOT_ACCEPTED" if binding_valid else "CONFLICT"
        )
        return {
            "recovery_status": recovery_status,
            "checkpoint_binding": checkpoint_result["checkpoint_binding"],
            "checkpoint_time_order": checkpoint_result["checkpoint_time_order"],
            "checkpoint_sequence": checkpoint["checkpoint_sequence"],
            "rollback_floor": floor_status,
            "acceptance_authentication": "NOT_VERIFIED",
            "storage_atomicity": "NOT_VERIFIED",
            "interpretation": (
                (
                    "A checkpoint payload is present without its acceptance receipt. "
                    "Treat it as prepared evidence, not as an accepted state. "
                )
                if binding_valid
                else (
                    "The checkpoint payload does not bind to the supplied event chain "
                    "or claims an anchor time before its event. Fail closed."
                )
            ) + (
                " Its sequence is below the independently supplied rollback floor."
                if floor_status == "BELOW_FLOOR"
                else " The supplied rollback floor is met or was not supplied."
            ),
        }

    _validate_receipt(acceptance_receipt)
    checkpoint_result = verify_external_checkpoint(events, checkpoint)
    checkpoint_digest = _canonical_checkpoint_sha256(checkpoint)
    sequence_matches = (
        acceptance_receipt["checkpoint_sequence"] == checkpoint["checkpoint_sequence"]
    )
    digest_matches = acceptance_receipt["checkpoint_sha256"] == checkpoint_digest
    accepted_at = _timestamp(
        acceptance_receipt["accepted_at_utc"], "acceptance_receipt.accepted_at_utc"
    )
    anchored_at = _timestamp(checkpoint["anchored_at_utc"], "checkpoint.anchored_at_utc")
    receipt_time_order = accepted_at >= anchored_at

    floor_status = "NOT_SUPPLIED"
    if minimum_sequence is not None:
        floor_status = (
            "MEETS_FLOOR"
            if checkpoint["checkpoint_sequence"] >= minimum_sequence
            else "BELOW_FLOOR"
        )

    if floor_status == "BELOW_FLOOR":
        status = "BELOW_FLOOR"
    elif (
        checkpoint_result["checkpoint_binding"] != "MATCH"
        or checkpoint_result["checkpoint_time_order"] != "NOT_BEFORE_EVENT"
        or not sequence_matches
        or not digest_matches
        or not receipt_time_order
    ):
        status = "CONFLICT"
    else:
        status = "CONSISTENT_UNAUTHENTICATED"

    return {
        "recovery_status": status,
        "checkpoint_binding": checkpoint_result["checkpoint_binding"],
        "receipt_sequence_matches": sequence_matches,
        "receipt_digest_matches": digest_matches,
        "receipt_time_order": "NOT_BEFORE_CHECKPOINT" if receipt_time_order else "PRECEDES_CHECKPOINT",
        "checkpoint_sequence": checkpoint["checkpoint_sequence"],
        "checkpoint_sha256": checkpoint_digest,
        "rollback_floor": floor_status,
        "acceptance_authentication": "NOT_VERIFIED",
        "storage_atomicity": "NOT_VERIFIED",
        "interpretation": (
            "The payload, receipt and supplied event chain are internally consistent. "
            "This is not proof that the receipt is authentic, that either copy is durable, "
            "or that the two writes were atomic."
            if status == "CONSISTENT_UNAUTHENTICATED"
            else "The retained state fails a recovery consistency or rollback check. "
            "Fail closed; do not promote this state to accepted."
        ),
    }
