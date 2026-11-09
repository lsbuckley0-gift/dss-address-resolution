"""Synthetic vehicle-event integrity benchmark for the ∂ss return-check principle.

This benchmark tests event/identity consistency, not real-world tracking accuracy.
All journeys are fictional and generated deterministically.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

GPS_LIMIT_METRES = 100.0
ANOMALIES = (
    "gps_drift",
    "wrong_parcel",
    "wrong_destination",
    "reordered_events",
    "missing_proof",
)


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


def evaluate_journey(journey: dict[str, Any]) -> dict[str, Any]:
    """Return VERIFIED only when all declared identity and event checks pass."""
    events = journey.get("events", [])
    checks: dict[str, bool] = {
        "expected_event_sequence": [e.get("type") for e in events]
        == ["pickup", "in_transit", "delivered"],
        "parcel_identity_preserved": bool(events) and all(
            e.get("parcel_id") == journey.get("expected_parcel_id") for e in events
        ),
        "destination_identity_preserved": bool(events) and all(
            e.get("destination_id") == journey.get("expected_destination_id") for e in events
        ),
        "timestamps_monotonic": bool(events) and all(
            isinstance(events[i].get("timestamp"), (int, float))
            and isinstance(events[i + 1].get("timestamp"), (int, float))
            and events[i]["timestamp"] <= events[i + 1]["timestamp"]
            for i in range(len(events) - 1)
        ),
        "delivery_within_gps_limit": bool(events) and isinstance(
            events[-1].get("gps_distance_m"), (int, float)
        ) and events[-1].get("gps_distance_m") <= GPS_LIMIT_METRES,
        "delivery_proof_present": bool(events) and bool(events[-1].get("proof_id")),
    }
    passed = all(checks.values())
    failed = [name for name, ok in checks.items() if not ok]
    return {
        "journey_id": journey.get("journey_id"),
        "terminal_state": "VERIFIED" if passed else "UNRESOLVED",
        "reason_codes": failed or ["ALL_DECLARED_CHECKS_PASSED"],
        "checks": checks,
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
    for journey in journeys:
        result = evaluate_journey(journey)
        expected = journey["injected_condition"]
        observed = result["terminal_state"]
        matrix[expected][observed] += 1
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
        "by_condition": {
            condition: dict(counts) for condition, counts in sorted(matrix.items())
        },
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
