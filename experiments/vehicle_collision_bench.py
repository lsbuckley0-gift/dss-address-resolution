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
