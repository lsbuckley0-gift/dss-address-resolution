"""Fail-closed comparison of endpoint fingerprints and claimed registration chronology.

This module validates record consistency and timestamp syntax. It does not
authenticate timestamp authorities, signatures, archives, or access logs.
"""
from __future__ import annotations

from datetime import datetime
import re

from experiments.pilot_metrics import _primary_endpoint_spec_sha256

_REQUIRED = {
    "record_version", "registration_reference", "endpoint_spec_sha256",
    "registered_at_utc", "outcomes_accessed_at_utc",
    "analysis_started_at_utc", "timestamp_evidence_reference",
}
_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)


def _utc_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError(f"{field} must be an ISO 8601 UTC timestamp ending in Z.")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid UTC timestamp.") from exc


def verify_registration_evidence(endpoint: dict, record: dict) -> dict:
    """Compare endpoint integrity and claimed event order without claiming trust."""
    if not isinstance(endpoint, dict):
        raise ValueError("endpoint must be an object.")
    if not isinstance(record, dict):
        raise ValueError("registration evidence must be an object.")
    missing = _REQUIRED - set(record)
    extra = set(record) - _REQUIRED
    if missing:
        raise ValueError("registration evidence missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("registration evidence contains unsupported field(s): " + ", ".join(sorted(extra)))
    if record["record_version"] != "registration-evidence/v1":
        raise ValueError("record_version must be registration-evidence/v1.")
    for field in ("registration_reference", "endpoint_spec_sha256", "timestamp_evidence_reference"):
        value = record[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string.")
    digest = record["endpoint_spec_sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("endpoint_spec_sha256 must be a lowercase SHA-256 hex digest.")
    registered = _utc_timestamp(record["registered_at_utc"], "registered_at_utc")
    outcomes_accessed = _utc_timestamp(
        record["outcomes_accessed_at_utc"], "outcomes_accessed_at_utc"
    )
    analysis_started = _utc_timestamp(
        record["analysis_started_at_utc"], "analysis_started_at_utc"
    )

    expected_digest = _primary_endpoint_spec_sha256(endpoint)
    reference_matches = (
        record["registration_reference"] == endpoint.get("registration_reference")
    )
    digest_matches = digest == expected_digest
    registered_before_access = registered < outcomes_accessed
    analysis_after_access = analysis_started > outcomes_accessed

    return {
        "specification_integrity": (
            "MATCH" if digest_matches and reference_matches else "MISMATCH"
        ),
        "digest_matches": digest_matches,
        "registration_reference_matches": reference_matches,
        "claimed_chronology": (
            "REGISTERED_BEFORE_OUTCOME_ACCESS"
            if registered_before_access else "NOT_REGISTERED_BEFORE_OUTCOME_ACCESS"
        ),
        "claimed_analysis_order": (
            "ANALYSIS_STRICTLY_AFTER_OUTCOME_ACCESS"
            if analysis_after_access else "ANALYSIS_NOT_STRICTLY_AFTER_OUTCOME_ACCESS"
        ),
        "timestamp_verification": "NOT_INDEPENDENTLY_VERIFIED",
        "timestamp_evidence_reference": record["timestamp_evidence_reference"],
        "interpretation": (
            "This result checks digest/reference consistency and the order claimed by "
            "the supplied timestamps. It does not authenticate the timestamp source, "
            "prove that outcomes were inaccessible, or verify an append-only access log."
        ),
    }
