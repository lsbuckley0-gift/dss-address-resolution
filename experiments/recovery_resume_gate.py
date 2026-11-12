"""Snapshot decision gate for an interrupted, operation-bound recovery.

The journal supplies durable local history; the sequence service supplies the
operation-attributed external outcome. Neither signal alone authorises resume.
"""
from __future__ import annotations

from enum import Enum
from os import PathLike

from experiments.recovery_operation_journal import inspect_recovery_operations
from experiments.recovery_sequence_contract import (
    RecoverySequenceBinding,
    SequenceConsumptionOutcome,
    SequenceConsumptionResult,
)


class RecoveryResumeDecision(str, Enum):
    ELIGIBLE_AT_CHECK = "AUTHORISED"
    BLOCKED_NOT_CONSUMED = "BLOCKED_NOT_CONSUMED"
    BLOCKED_INDETERMINATE = "BLOCKED_INDETERMINATE"


def evaluate_recovery_resume(
    journal_path: str | PathLike[str],
    binding: RecoverySequenceBinding,
    consumption: SequenceConsumptionResult,
) -> RecoveryResumeDecision:
    """Authorise classification only for the exact RUNNING operation and CONSUMED result.

    The journal is re-read and fully validated on every call. The returned decision\n    is a point-in-time eligibility result, not a lock or execution lease; callers\n    must serialize classification for an operation and make external side effects\n    idempotent or independently reconcilable. Its history
    validation also enforces that an attestation ID/sequence pair has one
    operation owner. A caller-supplied status dictionary is deliberately not
    accepted: the gate derives state from the persisted journal.
    """
    if not isinstance(binding, RecoverySequenceBinding):
        raise ValueError("binding must be a RecoverySequenceBinding.")
    if not isinstance(consumption, SequenceConsumptionResult):
        raise ValueError("consumption must be a typed SequenceConsumptionResult.")
    if consumption.binding != binding:
        raise ValueError("sequence outcome is bound to a different recovery operation.")

    operations = inspect_recovery_operations(journal_path)
    entry = operations.get(binding.operation_id)
    if entry is None:
        raise ValueError("operation binding is absent from the validated recovery journal.")

    expected = (
        binding.operation_id,
        binding.attestation_id,
        binding.attestation_sequence,
        binding.request_sha256,
    )
    observed = (
        entry["operation_id"],
        entry["attestation_id"],
        entry["attestation_sequence"],
        entry["request_sha256"],
    )
    if observed != expected:
        raise ValueError("persisted journal entry does not match the authoritative operation binding.")
    if entry["state"] != "RUNNING":
        raise ValueError("only an exact RUNNING journal operation can be resumed.")

    if consumption.outcome is SequenceConsumptionOutcome.CONSUMED:
        return RecoveryResumeDecision.AUTHORISED
    if consumption.outcome is SequenceConsumptionOutcome.NOT_CONSUMED:
        return RecoveryResumeDecision.BLOCKED_NOT_CONSUMED
    if consumption.outcome is SequenceConsumptionOutcome.INDETERMINATE:
        return RecoveryResumeDecision.BLOCKED_INDETERMINATE
    raise ValueError("unsupported sequence consumption outcome.")
