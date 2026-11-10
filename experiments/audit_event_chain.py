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
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
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


_CHECKPOINT_FIELDS = {
    "record_version", "registration_event_id", "checkpoint_sequence",
    "checkpoint_event_sha256", "anchored_at_utc", "anchor_reference",
}


def verify_external_checkpoint(events: list, checkpoint: dict) -> dict:
    """Compare a retained chain prefix with an independently held checkpoint claim."""
    verify_event_chain(events)
    if not events:
        raise ValueError("an external checkpoint cannot be compared with an empty event chain.")
    if not isinstance(checkpoint, dict):
        raise ValueError("checkpoint must be an object.")
    missing = _CHECKPOINT_FIELDS - set(checkpoint)
    extra = set(checkpoint) - _CHECKPOINT_FIELDS
    if missing:
        raise ValueError("checkpoint missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("checkpoint contains unsupported field(s): " + ", ".join(sorted(extra)))
    if checkpoint["record_version"] != "audit-chain-checkpoint/v1":
        raise ValueError("checkpoint record_version must be audit-chain-checkpoint/v1.")
    for field in ("registration_event_id", "checkpoint_event_sha256", "anchor_reference"):
        value = checkpoint[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"checkpoint {field} must be a non-empty string.")
    if not isinstance(checkpoint["checkpoint_event_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", checkpoint["checkpoint_event_sha256"]
    ):
        raise ValueError("checkpoint_event_sha256 must be a lowercase SHA-256 digest.")
    sequence = checkpoint["checkpoint_sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ValueError("checkpoint_sequence must be a non-negative integer.")
    anchored_at = _timestamp(checkpoint["anchored_at_utc"], "anchored_at_utc")
    if sequence >= len(events):
        return {
            "checkpoint_binding": "MISMATCH",
            "checkpoint_time_order": "NOT_COMPARABLE",
            "anchor_authentication": "NOT_VERIFIED",
            "anchor_reference": checkpoint["anchor_reference"],
            "interpretation": (
                "The retained event chain does not reach the checkpoint sequence. "
                "The checkpoint may expose truncation, but its authenticity is not verified."
            ),
        }

    event = events[sequence]
    registration_matches = events[0]["event_id"] == checkpoint["registration_event_id"]
    digest_matches = event["event_sha256"] == checkpoint["checkpoint_event_sha256"]
    event_time = _timestamp(event["occurred_at_utc"], "checkpoint event timestamp")
    time_order = "NOT_BEFORE_EVENT" if anchored_at >= event_time else "PRECEDES_EVENT"
    return {
        "checkpoint_binding": (
            "MATCH" if registration_matches and digest_matches else "MISMATCH"
        ),
        "registration_event_matches": registration_matches,
        "checkpoint_digest_matches": digest_matches,
        "checkpoint_time_order": time_order,
        "checkpoint_sequence": sequence,
        "anchor_authentication": "NOT_VERIFIED",
        "anchor_reference": checkpoint["anchor_reference"],
        "interpretation": (
            "This comparison checks whether the retained chain contains the event "
            "named by the checkpoint and whether the claimed anchor time is not earlier "
            "than that event. It does not authenticate the anchor, its timestamp, or "
            "the independent storage that is said to hold it."
        ),
    }


def verify_checkpoint_series(events: list, checkpoints: list) -> dict:
    """Verify multiple checkpoints bind one chain in strictly increasing order."""
    if not isinstance(checkpoints, list) or not checkpoints:
        raise ValueError("checkpoints must be a non-empty list.")
    results = []
    previous_sequence = -1
    previous_time = None
    seen_references = set()
    for index, checkpoint in enumerate(checkpoints):
        result = verify_external_checkpoint(events, checkpoint)
        sequence = checkpoint["checkpoint_sequence"]
        anchored_at = _timestamp(checkpoint["anchored_at_utc"], f"checkpoints[{index}].anchored_at_utc")
        reference = checkpoint["anchor_reference"]
        if sequence <= previous_sequence:
            result["series_order"] = "NON_INCREASING_SEQUENCE"
        elif previous_time is not None and anchored_at <= previous_time:
            result["series_order"] = "NON_INCREASING_ANCHOR_TIME"
        elif reference in seen_references:
            result["series_order"] = "DUPLICATE_ANCHOR_REFERENCE"
        else:
            result["series_order"] = "INCREASING"
        results.append(result)
        previous_sequence = sequence
        previous_time = anchored_at
        seen_references.add(reference)

    series_matches = all(
        result["checkpoint_binding"] == "MATCH"
        and result["checkpoint_time_order"] == "NOT_BEFORE_EVENT"
        and result.get("series_order") == "INCREASING"
        for result in results
    )
    return {
        "checkpoint_series_integrity": "MATCH" if series_matches else "MISMATCH",
        "checkpoint_count": len(results),
        "checkpoints": results,
        "anchor_authentication": "NOT_VERIFIED",
        "interpretation": (
            "Every supplied checkpoint is compared with the retained chain and the "
            "series is checked for increasing sequence, anchor time and distinct "
            "references. This does not authenticate any checkpoint authority or "
            "prove that unprovided checkpoints never existed."
        ),
    }


def verify_registration_chain_binding(endpoint: dict, registration_record: dict, events: list) -> dict:
    """Bind the frozen endpoint record to its registration event in a retained chain.

    The registration event ID is an explicit join key. This verifies that the
    supplied event chain begins with the event named by the registration record
    and that the record's endpoint fingerprint matches the endpoint supplied.
    It does not authenticate timestamps, actors, archives, or external anchors.
    """
    from experiments.registration_evidence import verify_registration_evidence

    registration = verify_registration_evidence(endpoint, registration_record)
    chain = verify_event_chain(events)
    event_id_matches = bool(events) and (
        events[0]["event_id"] == registration_record["registration_event_id"]
    )
    event_timestamp_matches = bool(events) and (
        _timestamp(events[0]["occurred_at_utc"], "registration event timestamp")
        == _timestamp(registration_record["registered_at_utc"], "registered_at_utc")
    )
    event_evidence_reference_matches = bool(events) and (
        events[0]["evidence_reference"]
        == registration_record["registration_event_evidence_reference"]
    )
    first_access_event = next(
        (event for event in events if event["event_type"] == "OUTCOME_ACCESS"),
        None,
    )
    analysis_event = next(
        (event for event in events if event["event_type"] == "ANALYSIS_STARTED"),
        None,
    )
    first_access_timestamp_matches = first_access_event is not None and (
        _timestamp(first_access_event["occurred_at_utc"], "first outcome-access timestamp")
        == _timestamp(registration_record["outcomes_accessed_at_utc"], "outcomes_accessed_at_utc")
    )
    analysis_timestamp_matches = analysis_event is not None and (
        _timestamp(analysis_event["occurred_at_utc"], "analysis-start timestamp")
        == _timestamp(registration_record["analysis_started_at_utc"], "analysis_started_at_utc")
    )
    binding = (
        "MATCH"
        if registration["specification_integrity"] == "MATCH"
        and event_id_matches and event_timestamp_matches
        and event_evidence_reference_matches
        and first_access_timestamp_matches and analysis_timestamp_matches
        else "MISMATCH"
    )
    return {
        "registration_chain_binding": binding,
        "registration_event_id_matches": event_id_matches,
        "registration_event_timestamp_matches": event_timestamp_matches,
        "registration_event_evidence_reference_matches": event_evidence_reference_matches,
        "first_outcome_access_timestamp_matches": first_access_timestamp_matches,
        "analysis_started_timestamp_matches": analysis_timestamp_matches,
        "registration_evidence": registration,
        "event_chain": chain,
        "timestamp_verification": "NOT_INDEPENDENTLY_VERIFIED",
        "interpretation": (
            "The endpoint fingerprint and registration reference are checked by "
            "the registration verifier, and the registration record's event ID is "
            "joined to the first event in the hash-linked chain. This does not "
            "authenticate the timestamp evidence, actor, archive, chain storage, "
            "or external checkpoint."
        ),
    }


def main(argv=None) -> int:
    """Verify an event-chain JSON file without modifying it."""
    import argparse
    from pathlib import Path
    import sys

    parser = argparse.ArgumentParser(
        description="Verify a retained ∂ss registration and outcome-access event chain."
    )
    parser.add_argument("event_chain", help="JSON file containing an array of audit events")
    checkpoint_group = parser.add_mutually_exclusive_group()
    checkpoint_group.add_argument("--checkpoint", help="Optional independently held checkpoint JSON file")
    checkpoint_group.add_argument("--checkpoints", help="Optional JSON array of independently held checkpoints")
    checkpoint_group.add_argument("--signed-checkpoint", help="Checkpoint JSON file with detached signature verification")
    parser.add_argument("--signature", help="Detached checkpoint signature-envelope JSON file")
    parser.add_argument("--trust-store", help="Explicit audit trust-store JSON file")
    parser.add_argument("--trust-store-pin", help="Out-of-band trust-store SHA-256 pin JSON file")
    parser.add_argument("--at-utc", help="Claimed UTC instant used for key-validity policy (not independently authenticated)")
    args = parser.parse_args(argv)
    signed_options = (args.signature, args.trust_store, args.at_utc)
    if args.signed_checkpoint and not all(signed_options):
        parser.error("--signed-checkpoint requires --signature, --trust-store and --at-utc")
    if not args.signed_checkpoint and (any(signed_options) or args.trust_store_pin):
        parser.error("--signature, --trust-store, --trust-store-pin and --at-utc require --signed-checkpoint")
    try:
        events = json.loads(Path(args.event_chain).read_text(encoding="utf-8"))
        report = verify_event_chain(events)
        if args.checkpoint:
            checkpoint = json.loads(Path(args.checkpoint).read_text(encoding="utf-8"))
            report["external_checkpoint"] = verify_external_checkpoint(events, checkpoint)
        if args.checkpoints:
            checkpoints = json.loads(Path(args.checkpoints).read_text(encoding="utf-8"))
            report["external_checkpoints"] = verify_checkpoint_series(events, checkpoints)
        if args.signed_checkpoint:
            from experiments.checkpoint_signature import verify_signed_checkpoint

            checkpoint = json.loads(Path(args.signed_checkpoint).read_text(encoding="utf-8"))
            signature = json.loads(Path(args.signature).read_text(encoding="utf-8"))
            trust_store = json.loads(Path(args.trust_store).read_text(encoding="utf-8"))
            trust_store_pin = (
                json.loads(Path(args.trust_store_pin).read_text(encoding="utf-8"))
                if args.trust_store_pin else None
            )
            report["signed_external_checkpoint"] = verify_signed_checkpoint(
                events, checkpoint, signature, trust_store, at_utc=args.at_utc,
                trust_store_pin=trust_store_pin,
            )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"audit event chain error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    checkpoint_ok = True
    if args.checkpoint:
        checkpoint_ok = (
            report["external_checkpoint"]["checkpoint_binding"] == "MATCH"
            and report["external_checkpoint"]["checkpoint_time_order"] == "NOT_BEFORE_EVENT"
        )
    if args.checkpoints:
        checkpoint_ok = report["external_checkpoints"]["checkpoint_series_integrity"] == "MATCH"
    if args.signed_checkpoint:
        checkpoint_ok = (
            report["signed_external_checkpoint"]["signed_checkpoint_verification"] == "MATCH"
        )
    return 0 if report["required_event_sequence"] == "COMPLETE" and checkpoint_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

