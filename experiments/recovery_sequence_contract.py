"""Operation-bound contract for independent recovery sequence services.

This module defines the identity and result shape required at the external
anti-replay boundary. It does not implement durable storage, atomicity,
idempotency, or failure-domain independence; those remain service obligations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RecoverySequenceBinding:
    """Immutable identity for one attempted recovery sequence consumption."""

    operation_id: str
    attestation_id: str
    attestation_sequence: int
    request_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or not _ID.fullmatch(self.operation_id):
            raise ValueError("operation_id must be a valid non-empty identifier.")
        if not isinstance(self.attestation_id, str) or not _ID.fullmatch(self.attestation_id):
            raise ValueError("attestation_id must be a valid non-empty identifier.")
        if (not isinstance(self.attestation_sequence, int)
                or isinstance(self.attestation_sequence, bool)
                or self.attestation_sequence < 1):
            raise ValueError("attestation_sequence must be a positive integer.")
        if not isinstance(self.request_sha256, str) or not _SHA256.fullmatch(self.request_sha256):
            raise ValueError("request_sha256 must be a lowercase SHA-256 hex digest.")


class SequenceConsumptionOutcome(str, Enum):
    CONSUMED = "CONSUMED"
    NOT_CONSUMED = "NOT_CONSUMED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class SequenceConsumptionResult:
    """An outcome explicitly attributed to the complete operation binding."""

    binding: RecoverySequenceBinding
    outcome: SequenceConsumptionOutcome

    def __post_init__(self) -> None:
        if not isinstance(self.binding, RecoverySequenceBinding):
            raise ValueError("result binding must be a RecoverySequenceBinding.")
        if not isinstance(self.outcome, SequenceConsumptionOutcome):
            raise ValueError("result outcome must be an explicit SequenceConsumptionOutcome.")


class IndependentRecoverySequenceService(Protocol):
    """Required interface; implementations must provide atomic, durable idempotency."""

    def consume(self, binding: RecoverySequenceBinding) -> SequenceConsumptionResult:
        """Atomically consume once for this exact binding, idempotently on retry."""
        ...

    def query(self, binding: RecoverySequenceBinding) -> SequenceConsumptionResult:
        """Return the durable outcome for this exact binding, or INDETERMINATE."""
        ...


def _checked_result(
    result: object, expected: RecoverySequenceBinding
) -> SequenceConsumptionResult:
    if not isinstance(result, SequenceConsumptionResult):
        raise ValueError("sequence service returned an untyped consumption result.")
    if result.binding != expected:
        raise ValueError("sequence service result is bound to a different recovery operation.")
    return result


def query_sequence_consumption(
    service: IndependentRecoverySequenceService,
    binding: RecoverySequenceBinding,
) -> SequenceConsumptionResult:
    """Query exact operation identity; service errors become INDETERMINATE."""
    query = getattr(service, "query", None)
    if not callable(query):
        raise ValueError("sequence service must provide query(binding).")
    try:
        result = query(binding)
    except Exception:
        return SequenceConsumptionResult(binding, SequenceConsumptionOutcome.INDETERMINATE)
    return _checked_result(result, binding)


def consume_or_reconcile_sequence(
    service: IndependentRecoverySequenceService,
    binding: RecoverySequenceBinding,
) -> SequenceConsumptionResult:
    """Consume by full binding; after an exception, query rather than guess.

    INDETERMINATE never authorises recovery. A caller may retry only with the
    identical binding and only if the service honours its idempotency contract.
    """
    consume = getattr(service, "consume", None)
    if not callable(consume):
        raise ValueError("sequence service must provide consume(binding).")
    try:
        result = consume(binding)
    except Exception:
        return query_sequence_consumption(service, binding)
    return _checked_result(result, binding)
