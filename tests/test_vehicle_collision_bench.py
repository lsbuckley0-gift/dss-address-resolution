import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))

from vehicle_collision_bench import (  # noqa: E402
    ANOMALIES, benchmark, evaluate_journey, generate_compound_dataset, generate_dataset, make_compound_journey, make_journey,
)


class VehicleCollisionBenchTests(unittest.TestCase):
    def test_clean_journey_is_verified(self):
        result = evaluate_journey(make_journey(1))
        self.assertEqual(result["terminal_state"], "VERIFIED")
        self.assertEqual(result["reason_codes"], ["ALL_DECLARED_CHECKS_PASSED"])

    def test_each_declared_disturbance_is_unresolved(self):
        for anomaly in ANOMALIES:
            with self.subTest(anomaly=anomaly):
                result = evaluate_journey(make_journey(2, anomaly))
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertNotEqual(result["reason_codes"], ["ALL_DECLARED_CHECKS_PASSED"])

    def test_benchmark_is_deterministic_and_balanced(self):
        first = generate_dataset(1000, seed=88)
        second = generate_dataset(1000, seed=88)
        self.assertEqual(first, second)
        report = benchmark(first)
        self.assertEqual(report["journey_count"], 1000)
        self.assertEqual(report["injected_anomaly_count"], 500)
        self.assertEqual(report["detected_anomaly_count"], 500)
        self.assertEqual(report["false_accept_count"], 0)
        self.assertEqual(report["false_reject_count"], 0)


    def test_missing_proof_is_classified_as_insufficient_evidence(self):
        result = evaluate_journey(make_journey(10, "missing_proof"))
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertEqual(result["evidence_class"], "INSUFFICIENT")
        self.assertIn("DELIVERY_PROOF_REFERENCE_MISSING", result["reason_codes"])

    def test_identity_mismatch_is_classified_as_conflicting_evidence(self):
        result = evaluate_journey(make_journey(11, "wrong_parcel"))
        self.assertEqual(result["evidence_class"], "CONFLICTING")
        self.assertIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])

    def test_missing_gps_and_wrong_identity_are_mixed_evidence(self):
        journey = make_journey(12)
        journey["events"][-1]["gps_distance_m"] = None
        journey["events"][-1]["parcel_id"] = "OTHER-PARCEL"
        result = evaluate_journey(journey)
        self.assertEqual(result["evidence_class"], "MIXED")
        self.assertIn("DELIVERY_GPS_MISSING", result["reason_codes"])
        self.assertIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])

    def test_boolean_is_not_accepted_as_timestamp_or_distance(self):
        journey = make_journey(13)
        journey["events"][-1]["timestamp"] = True
        journey["events"][-1]["gps_distance_m"] = True
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("TIMESTAMP_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("DELIVERY_GPS_INVALID", result["reason_codes"])

    def test_malformed_journey_and_event_records_return_refusal_traces(self):
        for malformed in (None, [], {"journey_id": "J-x", "events": [None]}):
            with self.subTest(malformed=malformed):
                result = evaluate_journey(malformed)
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertTrue(result["reason_codes"])

    def test_missing_or_blank_journey_and_expected_ids_are_refused(self):
        journey = make_journey(20)
        journey["journey_id"] = "  "
        journey["expected_parcel_id"] = ""
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("JOURNEY_ID_MISSING_OR_INVALID", result["reason_codes"])
        self.assertIn("EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID", result["reason_codes"])

    def test_duplicate_event_type_is_not_silently_reordered(self):
        journey = make_journey(21)
        journey["events"][1]["type"] = "pickup"
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("EVENT_SEQUENCE_MISMATCH", result["reason_codes"])

    def test_non_finite_and_negative_gps_distances_are_rejected(self):
        for distance in (-0.1, float("nan"), float("inf"), float("-inf")):
            with self.subTest(distance=distance):
                journey = make_journey(22)
                journey["events"][-1]["gps_distance_m"] = distance
                result = evaluate_journey(journey)
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertIn("DELIVERY_GPS_INVALID", result["reason_codes"])

    def test_gps_limit_is_inclusive_but_values_above_it_fail(self):
        journey = make_journey(23)
        journey["events"][-1]["gps_distance_m"] = 100.0
        self.assertEqual(evaluate_journey(journey)["terminal_state"], "VERIFIED")
        journey["events"][-1]["gps_distance_m"] = 100.0001
        self.assertEqual(evaluate_journey(journey)["terminal_state"], "UNRESOLVED")

    def test_compound_disturbances_are_unresolved(self):
        compound = make_compound_journey(3, ("gps_drift", "wrong_parcel", "missing_proof"))
        result = evaluate_journey(compound)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertFalse(result["checks"]["parcel_identity_preserved"])
        self.assertFalse(result["checks"]["delivery_within_gps_limit"])
        self.assertFalse(result["checks"]["delivery_proof_present"])

    def test_compound_benchmark_reports_pair_and_triple_failures(self):
        dataset = generate_compound_dataset(1200, seed=88)
        report = benchmark(dataset)
        self.assertEqual(report["journey_count"], 1200)
        self.assertEqual(report["injected_anomaly_count"], 800)
        self.assertEqual(report["detected_anomaly_count"], 800)
        self.assertEqual(report["false_accept_count"], 0)
        self.assertEqual(report["false_reject_count"], 0)
        self.assertTrue(any(k.startswith("compound:") for k in report["by_condition"]))

    def test_compound_generator_rejects_duplicate_anomalies(self):
        with self.assertRaises(ValueError):
            make_compound_journey(4, ("gps_drift", "gps_drift"))

    def test_invalid_dataset_size_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_dataset(999)


if __name__ == "__main__":
    unittest.main()
