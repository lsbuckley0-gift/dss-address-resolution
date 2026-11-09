"""Synthetic vehicle-event integrity benchmark for the ∂ss return-check principle.

This benchmark tests event/identity consistency, not real-world tracking accuracy.
All journeys are fictional and generated deterministically.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import random
from itertools import combinations
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Make the repository-level shared contract importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dss_core.evidence import classify_evidence

GPS_LIMIT_METRES = 100.0
ANOMALIES = (
    "gps_drift",
    "wrong_parcel",
    "wrong_destination",
    "reordered_events",
    "missing_proof",
)

# Explicit oracle mapping: injected synthetic disturbance -> invariant reason code.
# This mapping is benchmark metadata; the evaluator does not consult it.
ANOMALY_REASON_CODES = {
    "gps_drift": "DELIVERY_GPS_OUTSIDE_LIMIT",
    "wrong_parcel": "PARCEL_IDENTITY_CONFLICT",
    "wrong_destination": "DESTINATION_IDENTITY_CONFLICT",
    "reordered_events": "TIMESTAMP_ORDER_CONFLICT",
    "missing_proof": "DELIVERY_PROOF_REFERENCE_MISSING",
}

# Exact rule language is part of the provenance contract. The auditor checks
# this independently rather than accepting any non-empty explanation.
PROVENANCE_RULES = {
    "JOURNEY_ID_MISSING_OR_INVALID": "A non-empty journey identifier is required.",
    "EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID": "Both expected identity references are required for full verification.",
    "EXPECTED_PARCEL_ID_MISSING_OR_INVALID": "Expected parcel reference must be non-empty text.",
    "EXPECTED_DESTINATION_ID_MISSING_OR_INVALID": "Expected destination reference must be non-empty text.",
    "EVENT_RECORDS_MISSING_OR_INVALID": "Events must be a non-empty list of object records.",
    "EVENT_SEQUENCE_MISMATCH": "Observed event types must match pickup, in_transit, delivered in order.",
    "PARCEL_ID_MISSING_OR_INVALID": "Every event must carry a non-empty parcel identifier.",
    "PARCEL_IDENTITY_CONFLICT": "Observed parcel identifiers must equal expected_parcel_id.",
    "DESTINATION_ID_MISSING_OR_INVALID": "Every event must carry a non-empty destination identifier.",
    "DESTINATION_IDENTITY_CONFLICT": "Observed destination identifiers must equal expected_destination_id.",
    "TIMESTAMP_MISSING_OR_INVALID": "Exactly three finite numeric timestamps are required.",
    "TIMESTAMP_ORDER_CONFLICT": "Adjacent event timestamps must be non-decreasing.",
    "DELIVERY_GPS_MISSING": "A delivery GPS distance is required.",
    "DELIVERY_GPS_INVALID": "GPS distance must be a finite non-negative number.",
    "DELIVERY_GPS_OUTSIDE_LIMIT": f"Delivery GPS distance must be <= {GPS_LIMIT_METRES:g} metres.",
    "DELIVERY_PROOF_REFERENCE_MISSING": "A non-empty delivery proof reference is required.",
    "ALL_DECLARED_CHECKS_PASSED": "All declared checks passed; this is a success marker, not a failure.",
}


def _decode_injected_condition(condition: str) -> tuple[str, ...]:
    if condition == "clean":
        return ()
    if condition.startswith("compound:"):
        anomalies = tuple(condition.removeprefix("compound:").split("+"))
    else:
        anomalies = (condition,)
    if not anomalies or any(anomaly not in ANOMALY_REASON_CODES for anomaly in anomalies):
        raise ValueError(f"Unknown injected condition: {condition}")
    if len(set(anomalies)) != len(anomalies):
        raise ValueError(f"Duplicate anomaly in injected condition: {condition}")
    return anomalies


def apply_anomaly(events: list[dict[str, Any]], index: int, anomaly: str) -> None:
    """Apply one controlled disturbance to a fresh journey's event list."""
    delivery = events[-1]
    if anomaly == "gps_drift":
        delivery["gps_distance_m"] = 350.0
    elif anomaly == "wrong_parcel":
        delivery["parcel_id"] = f"OTHER-{index:06d}"
    elif anomaly == "wrong_destination":
        delivery["destination_id"] = f"OTHER-D-{index:06d}"
    elif anomaly == "reordered_events":
        delivery["timestamp"] = 1400
    elif anomaly == "missing_proof":
        delivery["proof_id"] = None
    else:
        raise ValueError(f"Unknown anomaly: {anomaly}")


def make_journey(index: int, anomaly: str = "clean") -> dict[str, Any]:
    parcel = f"P-{index:06d}"
    destination = f"D-{index:06d}"
    events = [
        {"type": "pickup", "parcel_id": parcel, "destination_id": destination,
         "timestamp": 1000, "gps_distance_m": None, "proof_id": None},
        {"type": "in_transit", "parcel_id": parcel, "destination_id": destination,
         "timestamp": 1600, "gps_distance_m": None, "proof_id": None},
        {"type": "delivered", "parcel_id": parcel, "destination_id": destination,
         "timestamp": 2200, "gps_distance_m": 12.0, "proof_id": f"PROOF-{index:06d}"},
    ]
    if anomaly != "clean":
        apply_anomaly(events, index, anomaly)
    return {
        "journey_id": f"J-{index:06d}",
        "expected_parcel_id": parcel,
        "expected_destination_id": destination,
        "injected_condition": anomaly,
        "events": events,
    }


def make_interaction_journey(
    index: int,
    primary_anomaly: str,
    interaction: str,
) -> dict[str, Any]:
    """Create a labelled interaction where a secondary symptom may mask or echo a fault.

    Oracle metadata is deliberately kept outside the event evidence consumed by
    evaluate_journey. Supported interactions are narrow, named test fixtures.
    """
    if primary_anomaly not in ANOMALY_REASON_CODES:
        raise ValueError(f"Unknown primary anomaly: {primary_anomaly}")
    journey = make_journey(index)
    apply_anomaly(journey["events"], index, primary_anomaly)

    if interaction == "sequence_echo" and primary_anomaly == "reordered_events":
        # Duplicate the event label without moving the delivery record, so
        # the sequence check fails while delivery GPS/proof remain attached.
        journey["events"][1]["type"] = "delivered"
        # Preserve the primary backwards-timestamp symptom as well.
        journey["events"][2]["timestamp"] = 1400
    elif interaction == "missing_parcel_masks_conflict" and primary_anomaly == "wrong_parcel":
        # Erase the only conflicting value: no evaluator can recover it from
        # the remaining evidence, so the missing-field reason is appropriate.
        journey["events"][-1]["parcel_id"] = ""
    elif interaction == "missing_parcel_with_separate_conflict" and primary_anomaly == "wrong_parcel":
        # Keep the wrong delivery identity but remove the middle event's parcel
        # field. The evaluator should report both independently observable facts.
        journey["events"][1]["parcel_id"] = ""
    elif interaction == "missing_destination_with_separate_conflict" and primary_anomaly == "wrong_destination":
        # Same precedence test for destination identity, independent of parcel logic.
        journey["events"][1]["destination_id"] = ""
    else:
        raise ValueError(
            f"Unsupported interaction {interaction!r} for {primary_anomaly!r}"
        )

    journey["injected_condition"] = primary_anomaly
    journey["injected_interaction"] = interaction
    return journey


def make_compound_journey(index: int, anomalies: tuple[str, ...]) -> dict[str, Any]:
    """Create a journey with multiple simultaneous, independently named disturbances."""
    if len(anomalies) < 2 or len(set(anomalies)) != len(anomalies):
        raise ValueError("A compound journey requires at least two distinct anomalies")
    unknown = set(anomalies) - set(ANOMALIES)
    if unknown:
        raise ValueError(f"Unknown anomalies: {sorted(unknown)}")
    journey = make_journey(index)
    for anomaly in anomalies:
        apply_anomaly(journey["events"], index, anomaly)
    journey["injected_condition"] = "compound:" + "+".join(sorted(anomalies))
    return journey


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _finite_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _evidence_provenance(journey: dict[str, Any], reason_codes: list[str]) -> list[dict[str, Any]]:
    """Attach field/event locations to evaluator findings without copying raw values.

    Event indices refer to positions in the original input list, including when
    malformed sibling records are skipped for independent evidence inspection.
    """
    raw_events = journey.get("events")
    indexed_events = (
        [(index, event) for index, event in enumerate(raw_events) if isinstance(event, dict)]
        if isinstance(raw_events, list) else []
    )
    expected_types = ["pickup", "in_transit", "delivered"]
    records: list[dict[str, Any]] = []

    def add(code: str, kind: str, source: str, fields: list[str],
            indices: list[int], rule: str) -> None:
        if code in reason_codes:
            records.append({
                "reason_code": code,
                "evidence_kind": kind,
                "source": source,
                "fields": fields,
                "event_indices": indices,
                "rule": rule,
            })

    if not _nonempty_text(journey.get("journey_id")):
        add("JOURNEY_ID_MISSING_OR_INVALID", "missing", "journey",
            ["journey_id"], [], "A non-empty journey identifier is required.")
    if not _nonempty_text(journey.get("expected_parcel_id")) or not _nonempty_text(journey.get("expected_destination_id")):
        add("EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID", "missing", "journey",
            ["expected_parcel_id", "expected_destination_id"], [],
            "Both expected identity references are required for full verification.")
    if not _nonempty_text(journey.get("expected_parcel_id")):
        add("EXPECTED_PARCEL_ID_MISSING_OR_INVALID", "missing", "journey",
            ["expected_parcel_id"], [], "Expected parcel reference must be non-empty text.")
    if not _nonempty_text(journey.get("expected_destination_id")):
        add("EXPECTED_DESTINATION_ID_MISSING_OR_INVALID", "missing", "journey",
            ["expected_destination_id"], [], "Expected destination reference must be non-empty text.")

    malformed = (
        [i for i, event in enumerate(raw_events) if not isinstance(event, dict)]
        if isinstance(raw_events, list) else []
    )
    if not isinstance(raw_events, list) or not raw_events or malformed:
        add("EVENT_RECORDS_MISSING_OR_INVALID", "missing", "events",
            ["events"], malformed, "Events must be a non-empty list of object records.")

    event_types = [event.get("type") for _, event in indexed_events]
    sequence_bad = [
        original_index for position, (original_index, event) in enumerate(indexed_events)
        if position >= len(expected_types) or event.get("type") != expected_types[position]
    ]
    if len(indexed_events) != len(expected_types):
        sequence_bad.extend(
            index for index, _ in indexed_events if index not in sequence_bad
        )
    add("EVENT_SEQUENCE_MISMATCH", "conflict", "events",
        ["type"], sorted(set(sequence_bad)),
        "Observed event types must match pickup, in_transit, delivered in order.")

    expected_parcel = journey.get("expected_parcel_id")
    parcel_missing = [i for i, event in indexed_events if not _nonempty_text(event.get("parcel_id"))]
    parcel_conflict = [
        i for i, event in indexed_events
        if _nonempty_text(expected_parcel) and _nonempty_text(event.get("parcel_id"))
        and event.get("parcel_id") != expected_parcel
    ]
    add("PARCEL_ID_MISSING_OR_INVALID", "missing", "events", ["parcel_id"],
        parcel_missing, "Every event must carry a non-empty parcel identifier.")
    add("PARCEL_IDENTITY_CONFLICT", "conflict", "events", ["parcel_id"],
        parcel_conflict, "Observed parcel identifiers must equal expected_parcel_id.")

    expected_destination = journey.get("expected_destination_id")
    destination_missing = [i for i, event in indexed_events if not _nonempty_text(event.get("destination_id"))]
    destination_conflict = [
        i for i, event in indexed_events
        if _nonempty_text(expected_destination) and _nonempty_text(event.get("destination_id"))
        and event.get("destination_id") != expected_destination
    ]
    add("DESTINATION_ID_MISSING_OR_INVALID", "missing", "events", ["destination_id"],
        destination_missing, "Every event must carry a non-empty destination identifier.")
    add("DESTINATION_IDENTITY_CONFLICT", "conflict", "events", ["destination_id"],
        destination_conflict, "Observed destination identifiers must equal expected_destination_id.")

    timestamp_missing = [
        i for i, event in indexed_events if not _finite_number(event.get("timestamp"))
    ]
    if len(indexed_events) != 3:
        timestamp_missing.extend(i for i, _ in indexed_events if i not in timestamp_missing)
    add("TIMESTAMP_MISSING_OR_INVALID", "missing", "events", ["timestamp"],
        sorted(set(timestamp_missing)), "Exactly three finite numeric timestamps are required.")
    timestamp_conflicts = [
        [indexed_events[position][0], indexed_events[position + 1][0]]
        for position in range(min(2, len(indexed_events) - 1))
        if _finite_number(indexed_events[position][1].get("timestamp"))
        and _finite_number(indexed_events[position + 1][1].get("timestamp"))
        and indexed_events[position][1]["timestamp"] > indexed_events[position + 1][1]["timestamp"]
    ]
    add("TIMESTAMP_ORDER_CONFLICT", "conflict", "events", ["timestamp"],
        sorted({i for pair in timestamp_conflicts for i in pair}),
        "Adjacent event timestamps must be non-decreasing.")

    last_index, last_event = indexed_events[-1] if indexed_events else (None, {})
    distance = last_event.get("gps_distance_m")
    if not indexed_events or distance is None:
        add("DELIVERY_GPS_MISSING", "missing", "events", ["gps_distance_m"],
            [last_index] if last_index is not None else [],
            "A delivery GPS distance is required.")
    elif not _finite_number(distance) or distance < 0:
        add("DELIVERY_GPS_INVALID", "conflict", "events", ["gps_distance_m"],
            [last_index], "GPS distance must be a finite non-negative number.")
    elif distance > GPS_LIMIT_METRES:
        add("DELIVERY_GPS_OUTSIDE_LIMIT", "conflict", "events", ["gps_distance_m"],
            [last_index], f"Delivery GPS distance must be <= {GPS_LIMIT_METRES:g} metres.")
    if not indexed_events or not _nonempty_text(last_event.get("proof_id")):
        add("DELIVERY_PROOF_REFERENCE_MISSING", "missing", "events", ["proof_id"],
            [last_index] if last_index is not None else [],
            "A non-empty delivery proof reference is required.")

    if "ALL_DECLARED_CHECKS_PASSED" in reason_codes:
        records.append({
            "reason_code": "ALL_DECLARED_CHECKS_PASSED",
            "evidence_kind": "consistent",
            "source": "journey",
            "fields": ["journey_id", "expected_parcel_id", "expected_destination_id",
                       "events", "type", "parcel_id", "destination_id", "timestamp",
                       "gps_distance_m", "proof_id"],
            "event_indices": [i for i, _ in indexed_events],
            "rule": "All declared checks passed; this is a success marker, not a failure.",
        })
    return sorted(records, key=lambda record: record["reason_code"])


def evaluate_journey(journey: Any) -> dict[str, Any]:
    """Evaluate a journey defensively; malformed input becomes a refusal trace.

    Missing evidence and malformed schema are classified as insufficient.
    Contradictory observations are classified as conflicting. No malformed
    record is allowed to escape as an evaluator exception.
    """
    if not isinstance(journey, dict):
        journey = {}

    raw_events = journey.get("events")
    events_well_formed = isinstance(raw_events, list) and all(
        isinstance(event, dict) for event in raw_events
    )
    # Retain individually valid observations even when a sibling record is
    # malformed; the schema defect must not erase independent evidence.
    events = (
        [event for event in raw_events if isinstance(event, dict)]
        if isinstance(raw_events, list) else []
    )
    expected_types = ["pickup", "in_transit", "delivered"]
    event_types = [event.get("type") for event in events]

    expected_parcel = journey.get("expected_parcel_id")
    expected_destination = journey.get("expected_destination_id")
    expected_parcel_valid = _nonempty_text(expected_parcel)
    expected_destination_valid = _nonempty_text(expected_destination)
    expected_ids_valid = expected_parcel_valid and expected_destination_valid
    journey_id_valid = _nonempty_text(journey.get("journey_id"))

    timestamps_valid = len(events) == 3 and all(
        _finite_number(event.get("timestamp")) for event in events
    )
    timestamps_monotonic = timestamps_valid and all(
        events[i]["timestamp"] <= events[i + 1]["timestamp"]
        for i in range(2)
    )

    distance = events[-1].get("gps_distance_m") if events else None
    gps_valid = _finite_number(distance) and distance >= 0
    gps_within_limit = gps_valid and distance <= GPS_LIMIT_METRES

    parcel_ids_present = bool(events) and all(
        _nonempty_text(event.get("parcel_id")) for event in events
    )
    destination_ids_present = bool(events) and all(
        _nonempty_text(event.get("destination_id")) for event in events
    )
    proof_present = bool(events) and _nonempty_text(events[-1].get("proof_id"))

    sequence_ok = event_types == expected_types
    parcel_identity_ok = (
        expected_parcel_valid and parcel_ids_present
        and all(event.get("parcel_id") == expected_parcel for event in events)
    )
    destination_identity_ok = (
        expected_destination_valid and destination_ids_present
        and all(event.get("destination_id") == expected_destination for event in events)
    )

    checks: dict[str, bool] = {
        "journey_id_present": journey_id_valid,
        "expected_identity_fields_present": expected_ids_valid,
        "expected_parcel_id_present": expected_parcel_valid,
        "expected_destination_id_present": expected_destination_valid,
        "event_records_well_formed": events_well_formed,
        "expected_event_sequence": sequence_ok,
        "parcel_identity_preserved": bool(parcel_identity_ok),
        "destination_identity_preserved": bool(destination_identity_ok),
        "timestamps_monotonic": bool(timestamps_monotonic),
        "delivery_within_gps_limit": bool(gps_within_limit),
        "delivery_proof_present": bool(proof_present),
    }

    missing: list[str] = []
    conflicts: list[str] = []
    if not journey_id_valid:
        missing.append("JOURNEY_ID_MISSING_OR_INVALID")
    if not expected_ids_valid:
        missing.append("EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID")
    if not expected_parcel_valid:
        missing.append("EXPECTED_PARCEL_ID_MISSING_OR_INVALID")
    if not expected_destination_valid:
        missing.append("EXPECTED_DESTINATION_ID_MISSING_OR_INVALID")
    if not events_well_formed or not events:
        missing.append("EVENT_RECORDS_MISSING_OR_INVALID")
    if not sequence_ok:
        conflicts.append("EVENT_SEQUENCE_MISMATCH")
    if events and not parcel_ids_present:
        missing.append("PARCEL_ID_MISSING_OR_INVALID")
    if events and expected_parcel_valid and any(
        _nonempty_text(event.get("parcel_id"))
        and event.get("parcel_id") != expected_parcel
        for event in events
    ):
        conflicts.append("PARCEL_IDENTITY_CONFLICT")
    if events and not destination_ids_present:
        missing.append("DESTINATION_ID_MISSING_OR_INVALID")
    if events and expected_destination_valid and any(
        _nonempty_text(event.get("destination_id"))
        and event.get("destination_id") != expected_destination
        for event in events
    ):
        conflicts.append("DESTINATION_IDENTITY_CONFLICT")
    if not timestamps_valid:
        missing.append("TIMESTAMP_MISSING_OR_INVALID")
    elif not timestamps_monotonic:
        conflicts.append("TIMESTAMP_ORDER_CONFLICT")
    if not events or distance is None:
        missing.append("DELIVERY_GPS_MISSING")
    elif not gps_valid:
        conflicts.append("DELIVERY_GPS_INVALID")
    elif not gps_within_limit:
        conflicts.append("DELIVERY_GPS_OUTSIDE_LIMIT")
    if not proof_present:
        missing.append("DELIVERY_PROOF_REFERENCE_MISSING")

    reasons = sorted(set(missing + conflicts))
    evidence_class = classify_evidence(
        missing=bool(missing),
        conflicting=bool(conflicts),
    )
    passed = evidence_class == "SUFFICIENT_AND_CONSISTENT" and all(checks.values())
    if passed:
        reasons = ["ALL_DECLARED_CHECKS_PASSED"]

    return {
        "journey_id": journey.get("journey_id") if journey_id_valid else None,
        "terminal_state": "VERIFIED" if passed else "UNRESOLVED",
        "evidence_class": evidence_class,
        "reason_codes": reasons,
        "checks": checks,
        "evidence_provenance": _evidence_provenance(journey, reasons),
    }



def _expected_provenance_pointer(
    journey: Any, reason_code: str
) -> tuple[str, str, list[str], list[int]] | None:
    """Independently derive pointers for every evaluator rule, including malformed input."""
    if not isinstance(journey, dict):
        journey = {}
    raw_events = journey.get("events")
    indexed = (
        [(i, event) for i, event in enumerate(raw_events) if isinstance(event, dict)]
        if isinstance(raw_events, list) else []
    )
    expected_types = ["pickup", "in_transit", "delivered"]

    def pointer(kind: str, fields: list[str], indices: list[int]):
        return (kind, "events", fields, indices)

    if reason_code == "JOURNEY_ID_MISSING_OR_INVALID":
        if not _nonempty_text(journey.get("journey_id")):
            return ("missing", "journey", ["journey_id"], [])
    elif reason_code == "EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID":
        if not _nonempty_text(journey.get("expected_parcel_id")) or not _nonempty_text(
            journey.get("expected_destination_id")
        ):
            return (
                "missing", "journey",
                ["expected_parcel_id", "expected_destination_id"], [],
            )
    elif reason_code == "EXPECTED_PARCEL_ID_MISSING_OR_INVALID":
        if not _nonempty_text(journey.get("expected_parcel_id")):
            return ("missing", "journey", ["expected_parcel_id"], [])
    elif reason_code == "EXPECTED_DESTINATION_ID_MISSING_OR_INVALID":
        if not _nonempty_text(journey.get("expected_destination_id")):
            return ("missing", "journey", ["expected_destination_id"], [])
    elif reason_code == "EVENT_RECORDS_MISSING_OR_INVALID":
        malformed = (
            [i for i, event in enumerate(raw_events) if not isinstance(event, dict)]
            if isinstance(raw_events, list) else []
        )
        if not isinstance(raw_events, list) or not raw_events or malformed:
            return pointer("missing", ["events"], malformed)
    elif reason_code == "EVENT_SEQUENCE_MISMATCH":
        bad = [
            original_index
            for position, (original_index, event) in enumerate(indexed)
            if position >= len(expected_types) or event.get("type") != expected_types[position]
        ]
        if len(indexed) != len(expected_types):
            bad.extend(index for index, _ in indexed if index not in bad)
        if [event.get("type") for _, event in indexed] != expected_types:
            return pointer("conflict", ["type"], sorted(set(bad)))
    elif reason_code == "PARCEL_ID_MISSING_OR_INVALID":
        indices = [i for i, event in indexed if not _nonempty_text(event.get("parcel_id"))]
        if indexed and indices:
            return pointer("missing", ["parcel_id"], indices)
    elif reason_code == "PARCEL_IDENTITY_CONFLICT":
        expected = journey.get("expected_parcel_id")
        indices = [
            i for i, event in indexed
            if _nonempty_text(expected) and _nonempty_text(event.get("parcel_id"))
            and event.get("parcel_id") != expected
        ]
        if _nonempty_text(expected) and indices:
            return pointer("conflict", ["parcel_id"], indices)
    elif reason_code == "DESTINATION_ID_MISSING_OR_INVALID":
        indices = [i for i, event in indexed if not _nonempty_text(event.get("destination_id"))]
        if indexed and indices:
            return pointer("missing", ["destination_id"], indices)
    elif reason_code == "DESTINATION_IDENTITY_CONFLICT":
        expected = journey.get("expected_destination_id")
        indices = [
            i for i, event in indexed
            if _nonempty_text(expected) and _nonempty_text(event.get("destination_id"))
            and event.get("destination_id") != expected
        ]
        if _nonempty_text(expected) and indices:
            return pointer("conflict", ["destination_id"], indices)
    elif reason_code == "TIMESTAMP_MISSING_OR_INVALID":
        indices = [i for i, event in indexed if not _finite_number(event.get("timestamp"))]
        if len(indexed) != 3:
            indices.extend(i for i, _ in indexed if i not in indices)
        if len(indexed) != 3 or any(
            not _finite_number(event.get("timestamp")) for _, event in indexed
        ):
            return pointer("missing", ["timestamp"], sorted(set(indices)))
    elif reason_code == "TIMESTAMP_ORDER_CONFLICT":
        if len(indexed) == 3 and all(
            _finite_number(event.get("timestamp")) for _, event in indexed
        ):
            pairs = [
                (indexed[pos][0], indexed[pos + 1][0])
                for pos in range(2)
                if indexed[pos][1]["timestamp"] > indexed[pos + 1][1]["timestamp"]
            ]
            indices = sorted({i for pair in pairs for i in pair})
            if indices:
                return pointer("conflict", ["timestamp"], indices)
    elif reason_code in {
        "DELIVERY_GPS_MISSING", "DELIVERY_GPS_INVALID", "DELIVERY_GPS_OUTSIDE_LIMIT"
    }:
        if not indexed:
            if reason_code == "DELIVERY_GPS_MISSING":
                return pointer("missing", ["gps_distance_m"], [])
        else:
            index, event = indexed[-1]
            value = event.get("gps_distance_m")
            if value is None and reason_code == "DELIVERY_GPS_MISSING":
                return pointer("missing", ["gps_distance_m"], [index])
            if value is not None and not _finite_number(value) or (
                _finite_number(value) and value < 0
            ):
                if reason_code == "DELIVERY_GPS_INVALID":
                    return pointer("conflict", ["gps_distance_m"], [index])
            elif _finite_number(value) and value > GPS_LIMIT_METRES:
                if reason_code == "DELIVERY_GPS_OUTSIDE_LIMIT":
                    return pointer("conflict", ["gps_distance_m"], [index])
    elif reason_code == "DELIVERY_PROOF_REFERENCE_MISSING":
        if not indexed or not _nonempty_text(indexed[-1][1].get("proof_id")):
            return pointer(
                "missing", ["proof_id"], [indexed[-1][0]] if indexed else []
            )
    elif reason_code == "ALL_DECLARED_CHECKS_PASSED":
        expected_parcel = journey.get("expected_parcel_id")
        expected_destination = journey.get("expected_destination_id")
        timestamps = [event.get("timestamp") for _, event in indexed]
        clean = (
            _nonempty_text(journey.get("journey_id"))
            and _nonempty_text(expected_parcel)
            and _nonempty_text(expected_destination)
            and isinstance(raw_events, list)
            and len(raw_events) == 3
            and all(isinstance(event, dict) for event in raw_events)
            and len(indexed) == 3
            and [event.get("type") for _, event in indexed] == expected_types
            and all(event.get("parcel_id") == expected_parcel for _, event in indexed)
            and all(event.get("destination_id") == expected_destination for _, event in indexed)
            and all(_finite_number(value) for value in timestamps)
            and all(timestamps[i] <= timestamps[i + 1] for i in range(2))
            and _finite_number(indexed[-1][1].get("gps_distance_m"))
            and 0 <= indexed[-1][1]["gps_distance_m"] <= GPS_LIMIT_METRES
            and _nonempty_text(indexed[-1][1].get("proof_id"))
        )
        if clean:
            return (
                "consistent", "journey",
                ["journey_id", "expected_parcel_id", "expected_destination_id",
                 "events", "type", "parcel_id", "destination_id", "timestamp",
                 "gps_distance_m", "proof_id"],
                [i for i, _ in indexed],
            )
    return None


def _expected_decision_contract(journey: Any) -> tuple[dict[str, bool], str, str]:
    """Independently derive check outcomes, evidence class and terminal state."""
    if not isinstance(journey, dict):
        journey = {}
    raw = journey.get("events")
    well_formed = isinstance(raw, list) and all(isinstance(e, dict) for e in raw)
    events = [e for e in raw if isinstance(e, dict)] if isinstance(raw, list) else []
    parcel = journey.get("expected_parcel_id")
    destination = journey.get("expected_destination_id")
    parcel_ok = _nonempty_text(parcel)
    destination_ok = _nonempty_text(destination)
    timestamps_ok = len(events) == 3 and all(
        _finite_number(e.get("timestamp")) for e in events
    )
    monotonic = timestamps_ok and all(
        events[i]["timestamp"] <= events[i + 1]["timestamp"] for i in range(2)
    )
    distance = events[-1].get("gps_distance_m") if events else None
    gps_ok = _finite_number(distance) and distance >= 0 and distance <= GPS_LIMIT_METRES
    parcel_present = bool(events) and all(_nonempty_text(e.get("parcel_id")) for e in events)
    destination_present = bool(events) and all(
        _nonempty_text(e.get("destination_id")) for e in events
    )
    proof_present = bool(events) and _nonempty_text(events[-1].get("proof_id"))
    checks = {
        "journey_id_present": _nonempty_text(journey.get("journey_id")),
        "expected_identity_fields_present": parcel_ok and destination_ok,
        "expected_parcel_id_present": parcel_ok,
        "expected_destination_id_present": destination_ok,
        "event_records_well_formed": well_formed,
        "expected_event_sequence": [e.get("type") for e in events] == [
            "pickup", "in_transit", "delivered"
        ],
        "parcel_identity_preserved": bool(
            parcel_ok and parcel_present and all(e.get("parcel_id") == parcel for e in events)
        ),
        "destination_identity_preserved": bool(
            destination_ok and destination_present
            and all(e.get("destination_id") == destination for e in events)
        ),
        "timestamps_monotonic": bool(monotonic),
        "delivery_within_gps_limit": bool(gps_ok),
        "delivery_proof_present": bool(proof_present),
    }
    missing = (
        not checks["journey_id_present"]
        or not checks["expected_identity_fields_present"]
        or not checks["event_records_well_formed"]
        or not events
        or (bool(events) and not parcel_present)
        or (bool(events) and not destination_present)
        or not timestamps_ok
        or not events or distance is None
        or not proof_present
    )
    conflicts = (
        not checks["expected_event_sequence"]
        or (bool(events) and parcel_ok and any(
            _nonempty_text(e.get("parcel_id")) and e.get("parcel_id") != parcel
            for e in events
        ))
        or (bool(events) and destination_ok and any(
            _nonempty_text(e.get("destination_id")) and e.get("destination_id") != destination
            for e in events
        ))
        or (timestamps_ok and not monotonic)
        or (bool(events) and distance is not None and (
            not _finite_number(distance) or distance < 0 or distance > GPS_LIMIT_METRES
        ))
    )
    evidence_class = classify_evidence(missing=missing, conflicting=conflicts)
    terminal_state = (
        "VERIFIED" if evidence_class == "SUFFICIENT_AND_CONSISTENT" and all(checks.values())
        else "UNRESOLVED"
    )
    return checks, evidence_class, terminal_state


def audit_provenance_trace(
    journey: Any, result: Any
) -> dict[str, Any]:
    """Check exact reason coverage and independently validate generated pointers."""
    if not isinstance(journey, dict):
        journey = {}
    malformed_result = not isinstance(result, dict)
    if malformed_result:
        result = {}
    reasons = result.get("reason_codes", [])
    entries = result.get("evidence_provenance", [])
    expected_checks, expected_class, expected_terminal = _expected_decision_contract(journey)
    decision_mismatches = []
    observed_checks = result.get("checks")
    if not isinstance(observed_checks, dict) or observed_checks != expected_checks:
        decision_mismatches.append("checks")
    if result.get("evidence_class") != expected_class:
        decision_mismatches.append("evidence_class")
    if result.get("terminal_state") != expected_terminal:
        decision_mismatches.append("terminal_state")
    if not isinstance(reasons, list):
        reasons = []
    if not isinstance(entries, list):
        entries = []
    invalid_reason_values = [code for code in reasons if not isinstance(code, str)]
    reason_counts = Counter(code for code in reasons if isinstance(code, str))
    independently_expected = {
        code for code in PROVENANCE_RULES
        if _expected_provenance_pointer(journey, code) is not None
    }
    unreported_reasons = sorted(independently_expected - set(reason_counts))
    unexpected_reasons = sorted(set(reason_counts) - independently_expected)
    entry_counts = Counter(
        entry.get("reason_code") for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("reason_code"), str)
    )
    missing = sorted(code for code, count in reason_counts.items()
                     for _ in range(max(0, count - entry_counts[code])))
    orphaned = sorted(code for code, count in entry_counts.items()
                      for _ in range(max(0, count - reason_counts[code])))
    duplicates = sorted(code for code, count in entry_counts.items() if count > 1)
    unsupported, invalid_pointers = [], []
    if malformed_result:
        unsupported.append("<malformed-result-object>")
    if not isinstance(result.get("reason_codes", []), list) or not isinstance(
        result.get("evidence_provenance", []), list
    ):
        unsupported.append("<malformed-trace-collections>")
    if invalid_reason_values:
        unsupported.extend("<invalid-reason-code>" for _ in invalid_reason_values)
    for entry in entries:
        if not isinstance(entry, dict):
            unsupported.append("<non-object-entry>")
            continue
        code = entry.get("reason_code")
        expected = (
            _expected_provenance_pointer(journey, code)
            if isinstance(code, str) else None
        )
        if expected is None:
            unsupported.append(code if isinstance(code, str) else "<invalid-reason-code>")
            continue
        kind, source, fields, indices = expected
        if (
            entry.get("evidence_kind") != kind or entry.get("source") != source
            or entry.get("fields") != fields or entry.get("event_indices") != indices
            or entry.get("rule") != PROVENANCE_RULES.get(code)
        ):
            invalid_pointers.append(code)
        raw_events = journey.get("events")
        event_indices = entry.get("event_indices")
        if not isinstance(event_indices, list):
            invalid_pointers.append(code)
            continue
        if any(
            not isinstance(index, int) or isinstance(index, bool)
            or not isinstance(raw_events, list) or index < 0 or index >= len(raw_events)
            for index in event_indices
        ):
            invalid_pointers.append(code)
    event_reason_counts = Counter(
        index for entry in entries if isinstance(entry, dict)
        and isinstance(entry.get("event_indices"), list)
        for index in entry["event_indices"]
        if isinstance(index, int) and not isinstance(index, bool)
    )
    shared_event_indices = sorted(
        index for index, count in event_reason_counts.items() if count > 1
    )
    distinct_findings = len(set(reason_counts) - {"ALL_DECLARED_CHECKS_PASSED"})
    return {
        "valid": not (
            missing or orphaned or duplicates or unsupported or invalid_pointers
            or unreported_reasons or unexpected_reasons or decision_mismatches
        ),
        "decision_mismatches": decision_mismatches,
        "reason_count": len(reasons),
        "unreported_reason_codes": unreported_reasons,
        "unexpected_reason_codes": unexpected_reasons,
        "provenance_entry_count": len(entries),
        "missing_reason_entries": missing,
        "orphaned_provenance_entries": orphaned,
        "duplicate_reason_entries": duplicates,
        "unsupported_findings": unsupported,
        "invalid_evidence_pointers": sorted(set(invalid_pointers)),
        "shared_event_indices": shared_event_indices,
        "distinct_finding_count": distinct_findings,
    }


def audit_provenance(
    journeys: list[dict[str, Any]], results: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Audit dataset traces without consulting injected oracle labels."""
    if not isinstance(journeys, list):
        raise TypeError("journeys must be a list")
    if results is not None and not isinstance(results, list):
        raise TypeError("results must be a list or None")
    evaluated = results if results is not None else [
        evaluate_journey(journey) for journey in journeys
    ]
    if len(evaluated) != len(journeys):
        raise ValueError("results must contain exactly one trace per journey")
    traces = [audit_provenance_trace(j, r) for j, r in zip(journeys, evaluated)]
    return {
        "journey_count": len(journeys),
        "valid_journey_count": sum(trace["valid"] for trace in traces),
        "invalid_journey_count": sum(not trace["valid"] for trace in traces),
        "reason_count": sum(trace["reason_count"] for trace in traces),
        "provenance_entry_count": sum(trace["provenance_entry_count"] for trace in traces),
        "missing_reason_entry_count": sum(len(trace["missing_reason_entries"]) for trace in traces),
        "orphaned_entry_count": sum(len(trace["orphaned_provenance_entries"]) for trace in traces),
        "duplicate_entry_count": sum(len(trace["duplicate_reason_entries"]) for trace in traces),
        "unsupported_finding_count": sum(len(trace["unsupported_findings"]) for trace in traces),
        "invalid_pointer_count": sum(len(trace["invalid_evidence_pointers"]) for trace in traces),
        "unreported_reason_count": sum(len(trace["unreported_reason_codes"]) for trace in traces),
        "unexpected_reason_count": sum(len(trace["unexpected_reason_codes"]) for trace in traces),
        "decision_mismatch_count": sum(len(trace["decision_mismatches"]) for trace in traces),
        "journeys_with_shared_event_findings": sum(
            bool(trace["shared_event_indices"]) for trace in traces
        ),
        "shared_event_reference_count": sum(
            len(trace["shared_event_indices"]) for trace in traces
        ),
        "all_findings_distinct_by_reason_code": all(
            not trace["duplicate_reason_entries"] for trace in traces
        ),
    }


def benchmark_diagnostic_record(
    injected_anomalies: tuple[str, ...], result: dict[str, Any]
) -> dict[str, Any]:
    """Build an oracle-relative diagnostic trace outside the evaluator.

    The evaluator sees only journey evidence. This function compares its output
    with synthetic labels after evaluation, without feeding labels back into it.
    """
    observed = [
        code for code in result["reason_codes"]
        if code != "ALL_DECLARED_CHECKS_PASSED"
    ]
    if not injected_anomalies:
        return {
            "injected_faults": [],
            "primary_fault": None,
            "expected_reason_code": None,
            "primary_fault_detected": None,
            "observed_reason_codes": observed,
            "secondary_symptoms": [],
            "diagnostic_status": "CLEAN",
        }

    if len(injected_anomalies) != 1:
        return {
            "injected_faults": list(injected_anomalies),
            "primary_fault": None,
            "expected_reason_code": None,
            "primary_fault_detected": None,
            "observed_reason_codes": observed,
            "secondary_symptoms": observed,
            "diagnostic_status": "UNATTRIBUTED",
        }

    primary = injected_anomalies[0]
    expected = ANOMALY_REASON_CODES[primary]
    detected = expected in observed
    secondary = [code for code in observed if code != expected]
    if detected and secondary:
        status = "PRIMARY_IDENTIFIED_WITH_SYMPTOMS"
    elif detected:
        status = "PRIMARY_IDENTIFIED"
    elif result["terminal_state"] == "UNRESOLVED":
        status = "PRIMARY_MASKED"
    else:
        status = "UNATTRIBUTED"

    return {
        "injected_faults": [primary],
        "primary_fault": primary,
        "expected_reason_code": expected,
        "primary_fault_detected": detected,
        "observed_reason_codes": observed,
        "secondary_symptoms": secondary,
        "diagnostic_status": status,
    }


def generate_dataset(total: int = 10_000, seed: int = 88) -> list[dict[str, Any]]:
    """Generate 50% clean and evenly distributed injected-anomaly journeys."""
    if total < 2 or total % 2:
        raise ValueError("total must be an even integer of at least 2")
    anomaly_count = total // 2
    if anomaly_count % len(ANOMALIES):
        raise ValueError("total/2 must be divisible by the number of anomaly classes")

    per_class = anomaly_count // len(ANOMALIES)
    journeys = [make_journey(i, "clean") for i in range(total - anomaly_count)]
    next_id = total - anomaly_count
    for anomaly in ANOMALIES:
        for _ in range(per_class):
            journeys.append(make_journey(next_id, anomaly))
            next_id += 1
    random.Random(seed).shuffle(journeys)
    return journeys


def benchmark(journeys: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes = []
    matrix: dict[str, Counter[str]] = defaultdict(Counter)
    reason_counts: Counter[str] = Counter()
    reason_combinations: Counter[str] = Counter()
    condition_reason_counts: dict[str, Counter[str]] = defaultdict(Counter)
    condition_reason_combinations: dict[str, Counter[str]] = defaultdict(Counter)
    anomaly_reason_matrix: dict[str, Counter[str]] = {
        anomaly: Counter() for anomaly in ANOMALIES
    }
    anomaly_occurrences: Counter[str] = Counter()
    anomaly_detected: Counter[str] = Counter()
    clean_reason_counts: Counter[str] = Counter()
    interaction_reason_combinations: dict[str, Counter[str]] = defaultdict(Counter)
    diagnostic_status_counts: Counter[str] = Counter()
    diagnostic_records: list[dict[str, Any]] = []
    pair_interaction_stats: dict[tuple[str, str], dict[str, Any]] = {}
    interaction_diagnostic_stats: dict[str, dict[str, Any]] = {}

    for journey in journeys:
        result = evaluate_journey(journey)
        # injected_condition is benchmark oracle metadata only. It labels the
        # generated case; evaluate_journey never reads it when deciding outcome.
        expected = journey["injected_condition"]
        injected_anomalies = _decode_injected_condition(expected)
        observed = result["terminal_state"]
        matrix[expected][observed] += 1

        reasons = tuple(sorted(result["reason_codes"]))
        diagnostic = benchmark_diagnostic_record(injected_anomalies, result)
        diagnostic_status_counts[diagnostic["diagnostic_status"]] += 1
        diagnostic_records.append({
            "journey_id": result["journey_id"],
            **diagnostic,
        })
        combination = " + ".join(reasons)
        reason_counts.update(reasons)
        reason_combinations[combination] += 1
        condition_reason_counts[expected].update(reasons)
        condition_reason_combinations[expected][combination] += 1
        interaction = journey.get("injected_interaction")
        if interaction is not None:
            interaction_reason_combinations[interaction][combination] += 1
            stats = interaction_diagnostic_stats.setdefault(interaction, {
                "case_count": 0,
                "diagnostic_status_counts": Counter(),
                "primary_fault_detected_count": 0,
                "primary_fault_missed_count": 0,
                "secondary_symptom_counts": Counter(),
            })
            stats["case_count"] += 1
            stats["diagnostic_status_counts"][diagnostic["diagnostic_status"]] += 1
            if diagnostic["primary_fault_detected"] is True:
                stats["primary_fault_detected_count"] += 1
            elif diagnostic["primary_fault_detected"] is False:
                stats["primary_fault_missed_count"] += 1
            stats["secondary_symptom_counts"].update(diagnostic["secondary_symptoms"])
        if not injected_anomalies:
            clean_reason_counts.update(
                reason for reason in reasons
                if reason != "ALL_DECLARED_CHECKS_PASSED"
            )
        for anomaly in injected_anomalies:
            expected_reason = ANOMALY_REASON_CODES[anomaly]
            anomaly_occurrences[anomaly] += 1
            anomaly_reason_matrix[anomaly].update(reasons)
            if expected_reason in reasons:
                anomaly_detected[anomaly] += 1

        # Pairwise interaction statistics are computed after evaluation from
        # oracle labels and observed reason codes; labels never enter evaluator.
        for first, second in combinations(sorted(injected_anomalies), 2):
            key = (first, second)
            stats = pair_interaction_stats.setdefault(key, {
                "journey_count": 0,
                "both_detected": 0,
                "first_only": 0,
                "second_only": 0,
                "neither_detected": 0,
                "observed_reason_codes": Counter(),
                "terminal_states": Counter(),
            })
            first_detected = ANOMALY_REASON_CODES[first] in reasons
            second_detected = ANOMALY_REASON_CODES[second] in reasons
            stats["journey_count"] += 1
            stats["observed_reason_codes"].update(reasons)
            stats["terminal_states"].update([observed])
            if first_detected and second_detected:
                stats["both_detected"] += 1
            elif first_detected:
                stats["first_only"] += 1
            elif second_detected:
                stats["second_only"] += 1
            else:
                stats["neither_detected"] += 1
        outcomes.append(result)

    clean = matrix["clean"]
    injected_conditions = [condition for condition in matrix if condition != "clean"]
    injected = sum(sum(matrix[a].values()) for a in injected_conditions)
    detected = sum(matrix[a]["UNRESOLVED"] for a in injected_conditions)
    false_rejects = clean["UNRESOLVED"]
    false_accepts = sum(matrix[a]["VERIFIED"] for a in injected_conditions)
    return {
        "journey_count": len(journeys),
        "verified_count": sum(1 for r in outcomes if r["terminal_state"] == "VERIFIED"),
        "unresolved_count": sum(1 for r in outcomes if r["terminal_state"] == "UNRESOLVED"),
        "injected_anomaly_count": injected,
        "detected_anomaly_count": detected,
        "false_accept_count": false_accepts,
        "false_reject_count": false_rejects,
        "anomaly_detection_rate": detected / injected if injected else None,
        "clean_acceptance_rate": clean["VERIFIED"] / sum(clean.values()) if sum(clean.values()) else None,
        # by_condition is the oracle-condition x evaluator-terminal-state matrix.
        "by_condition": {
            condition: dict(counts) for condition, counts in sorted(matrix.items())
        },
        "reason_code_counts": dict(sorted(reason_counts.items())),
        "reason_combinations": dict(sorted(reason_combinations.items())),
        "condition_reason_code_counts": {
            condition: dict(sorted(counts.items()))
            for condition, counts in sorted(condition_reason_counts.items())
        },
        "condition_reason_combinations": {
            condition: dict(sorted(counts.items()))
            for condition, counts in sorted(condition_reason_combinations.items())
        },
        # Rows are injected anomaly labels; columns are evaluator reason codes.
        "anomaly_reason_matrix": {
            anomaly: dict(sorted(counts.items()))
            for anomaly, counts in sorted(anomaly_reason_matrix.items())
        },
        "anomaly_detection": {
            anomaly: {
                "expected_reason_code": ANOMALY_REASON_CODES[anomaly],
                "injected_occurrences": anomaly_occurrences[anomaly],
                "detected_occurrences": anomaly_detected[anomaly],
                "missed_occurrences": anomaly_occurrences[anomaly] - anomaly_detected[anomaly],
                "detection_rate": (
                    anomaly_detected[anomaly] / anomaly_occurrences[anomaly]
                    if anomaly_occurrences[anomaly] else None
                ),
            }
            for anomaly in sorted(ANOMALIES)
        },
        "clean_reason_code_counts": dict(sorted(clean_reason_counts.items())),
        "pair_interaction_matrix": {
            f"{first} + {second}": {
                "anomalies": [first, second],
                "expected_reason_codes": {
                    first: ANOMALY_REASON_CODES[first],
                    second: ANOMALY_REASON_CODES[second],
                },
                "journey_count": stats["journey_count"],
                "both_detected": stats["both_detected"],
                "first_only": stats["first_only"],
                "second_only": stats["second_only"],
                "neither_detected": stats["neither_detected"],
                "first_detection_rate": (
                    (stats["both_detected"] + stats["first_only"]) / stats["journey_count"]
                ),
                "second_detection_rate": (
                    (stats["both_detected"] + stats["second_only"]) / stats["journey_count"]
                ),
                "joint_detection_rate": stats["both_detected"] / stats["journey_count"],
                "observed_reason_code_counts": dict(sorted(stats["observed_reason_codes"].items())),
                "terminal_state_counts": dict(sorted(stats["terminal_states"].items())),
            }
            for (first, second), stats in sorted(pair_interaction_stats.items())
        },
        "interaction_reason_combinations": {
            interaction: dict(sorted(counts.items()))
            for interaction, counts in sorted(interaction_reason_combinations.items())
        },
        "interaction_diagnostic_summary": {
            interaction: {
                "case_count": stats["case_count"],
                "diagnostic_status_counts": dict(sorted(stats["diagnostic_status_counts"].items())),
                "primary_fault_detected_count": stats["primary_fault_detected_count"],
                "primary_fault_missed_count": stats["primary_fault_missed_count"],
                "secondary_symptom_counts": dict(sorted(stats["secondary_symptom_counts"].items())),
            }
            for interaction, stats in sorted(interaction_diagnostic_stats.items())
        },
        # Oracle-relative traces are generated after evaluate_journey returns.
        "diagnostic_status_counts": dict(sorted(diagnostic_status_counts.items())),
        "diagnostic_records": sorted(
            diagnostic_records, key=lambda record: (record["journey_id"] or "")
        ),
        "provenance_audit": audit_provenance(journeys, outcomes),
    }


def generate_compound_dataset(total: int = 1000, seed: int = 88) -> list[dict[str, Any]]:
    """Generate balanced clean, two-anomaly and three-anomaly journeys."""
    from itertools import combinations

    pairs = list(combinations(ANOMALIES, 2))
    triples = list(combinations(ANOMALIES, 3))
    groups = [(combo, "pair") for combo in pairs] + [(combo, "triple") for combo in triples]
    if total < len(groups) or total % 3:
        raise ValueError("total must be at least 25 and divisible by 3")
    compound_count = 2 * total // 3
    per_group = compound_count // len(groups)
    if per_group * len(groups) != compound_count:
        raise ValueError("total/3 must be divisible by the number of compound groups")

    clean_count = total // 3
    journeys = [make_journey(i, "clean") for i in range(clean_count)]
    next_id = clean_count
    for combo, _kind in groups:
        for _ in range(per_group):
            journeys.append(make_compound_journey(next_id, combo))
            next_id += 1
    random.Random(seed).shuffle(journeys)
    return journeys


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the synthetic ∂ss vehicle-event benchmark.")
    parser.add_argument("--total", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=88)
    parser.add_argument("--json-out", help="Optional path for the benchmark report.")
    args = parser.parse_args()
    report = benchmark(generate_dataset(args.total, args.seed))
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
