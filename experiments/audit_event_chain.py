"""Tamper-evident event-chain primitives for registration and outcome access.

The chain detects edits to a retained sequence. It does not authenticate actors,
timestamps, storage, or the existence of events omitted from the supplied log.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re

GENESIS_SHA256 = "0" * 64
RECORD_VERSION = "audit-event/v1"
_EVENT_TYPES = {"REGISTRATION_FROZEN", "OUTCOME_ACCESS", "ANALYSIS_STARTED"}
_REQUIRED_FIELDS = {
    "record_version", "sequence", "event_id", "event_type",
    "occurred_at_utc", "actor_reference", "evidence_reference",
    "previous_event_sha256", "event_sha256",
}
_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError(f"{field} must be an ISO 8601 UTC timestamp ending in Z.")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid UTC timestamp.") from exc


def _canonical_sha256(record: dict) -> str:
    payload = {key: value for key, value in record.items() if key != "event_sha256"}
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_event_chain(events: list) -> dict:
    """Verify a retained chain prefix and the required event ordering."""
    if not isinstance(events, list):
        raise ValueError("events must be a list.")
    previous_hash = GENESIS_SHA256
    previous_time = None
    seen_ids = set()
    registered = False
    first_access = False
    analysis_started = False

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"event at index {index} must be an object.")
        missing = _REQUIRED_FIELDS - set(event)
        extra = set(event) - _REQUIRED_FIELDS
        if missing:
            raise ValueError(f"event at index {index} missing field(s): " + ", ".join(sorted(missing)))
        if extra:
            raise ValueError(f"event at index {index} has unsupported field(s): " + ", ".join(sorted(extra)))
        if event["record_version"] != RECORD_VERSION:
            raise ValueError(f"event at index {index} has an unsupported record_version.")
        if isinstance(event["sequence"], bool) or not isinstance(event["sequence"], int) or event["sequence"] != index:
            raise ValueError(f"event at index {index} has a non-contiguous sequence.")
        event_id = event["event_id"]
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError(f"event at index {index} event_id must be non-empty.")
        if event_id in seen_ids:
            raise ValueError(f"duplicate event_id: {event_id}")
        seen_ids.add(event_id)
        for field in ("actor_reference", "evidence_reference"):
            value = event[field]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"event at index {index} {field} must be non-empty.")
        occurred = _timestamp(event["occurred_at_utc"], f"event[{index}].occurred_at_utc")
        if previous_time is not None and occurred <= previous_time:
            raise ValueError("event timestamps must be strictly increasing.")
        previous_time = occurred

        event_type = event["event_type"]
        if not isinstance(event_type, str) or event_type not in _EVENT_TYPES:
            raise ValueError(f"event at index {index} has an unsupported event_type.")
        if event_type == "REGISTRATION_FROZEN":
            if registered or index != 0:
                raise ValueError("REGISTRATION_FROZEN must occur exactly once as the first event.")
            registered = True
        elif event_type == "OUTCOME_ACCESS":
            if not registered:
                raise ValueError("OUTCOME_ACCESS requires a preceding REGISTRATION_FROZEN event.")
            first_access = True
        elif event_type == "ANALYSIS_STARTED":
            if not registered or not first_access:
                raise ValueError("ANALYSIS_STARTED requires prior registration and outcome access.")
            if analysis_started:
                raise ValueError("ANALYSIS_STARTED may occur only once.")
            analysis_started = True

        if event["previous_event_sha256"] != previous_hash:
            raise ValueError(f"event at index {index} previous_event_sha256 does not match chain.")
        digest = event["event_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"event at index {index} event_sha256 must be a lowercase SHA-256 digest.")
        calculated = _canonical_sha256(event)
        if digest != calculated:
            raise ValueError(f"event at index {index} event_sha256 does not match event content.")
        previous_hash = digest

    complete = registered and first_access and analysis_started
    return {
        "chain_integrity": "VALID_PREFIX",
        "event_count": len(events),
        "chain_head_sha256": previous_hash,
        "required_event_sequence": "COMPLETE" if complete else "INCOMPLETE",
        "registration_frozen": registered,
        "outcome_access_recorded": first_access,
        "analysis_started": analysis_started,
        "external_anchor_verification": "NOT_VERIFIED",
        "interpretation": (
            "The supplied retained prefix is internally hash-linked and follows the "
            "event-order rules. This does not prove that events are true, that no "
            "suffix was deleted, or that the chain head was independently anchored."
        ),
    }


def append_audit_event(
    events: list,
    *,
    event_id: str,
    event_type: str,
    occurred_at_utc: str,
    actor_reference: str,
    evidence_reference: str,
) -> list:
    """Return a new chain with one event; persistence is deliberately external."""
    current = verify_event_chain(events)
    if not isinstance(event_id, str) or not event_id.strip():
        raise ValueError("event_id must be a non-empty string.")
    if not isinstance(actor_reference, str) or not actor_reference.strip():
        raise ValueError("actor_reference must be a non-empty string.")
    if not isinstance(evidence_reference, str) or not evidence_reference.strip():
        raise ValueError("evidence_reference must be a non-empty string.")
    occurred = _timestamp(occurred_at_utc, "occurred_at_utc")
    if events:
        last = _timestamp(events[-1]["occurred_at_utc"], "last event timestamp")
        if occurred <= last:
            raise ValueError("new event timestamp must be strictly later than the chain head.")
    if not isinstance(event_type, str) or event_type not in _EVENT_TYPES:
        raise ValueError("unsupported event_type.")
    if any(event["event_id"] == event_id for event in events):
        raise ValueError(f"duplicate event_id: {event_id}")

    record = {
        "record_version": RECORD_VERSION,
        "sequence": len(events),
        "event_id": event_id,
        "event_type": event_type,
        "occurred_at_utc": occurred_at_utc,
        "actor_reference": actor_reference,
        "evidence_reference": evidence_reference,
        "previous_event_sha256": current["chain_head_sha256"],
    }
    record["event_sha256"] = _canonical_sha256(record)
    candidate = [*events, record]
    verify_event_chain(candidate)
    return candidate
