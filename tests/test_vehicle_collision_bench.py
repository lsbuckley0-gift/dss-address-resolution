import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))

from vehicle_collision_bench import (  # noqa: E402
    ANOMALIES, benchmark, evaluate_journey, generate_compound_dataset, generate_dataset, make_compound_journey, make_interaction_journey, make_journey,
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
        self.assertEqual(report["diagnostic_status_counts"], {
            "CLEAN": 400,
            "UNATTRIBUTED": 800,
        })
        self.assertEqual(len(report["diagnostic_records"]), 1200)
        self.assertEqual(
            len({record["journey_id"] for record in report["diagnostic_records"]}),
            1200,
        )

    def test_single_anomaly_report_has_exact_reason_frequencies(self):
        report = benchmark(generate_dataset(1000, seed=88))
        self.assertEqual(report["reason_code_counts"], {
            "ALL_DECLARED_CHECKS_PASSED": 500,
            "DELIVERY_GPS_OUTSIDE_LIMIT": 100,
            "DELIVERY_PROOF_REFERENCE_MISSING": 100,
            "DESTINATION_IDENTITY_CONFLICT": 100,
            "PARCEL_IDENTITY_CONFLICT": 100,
            "TIMESTAMP_ORDER_CONFLICT": 100,
        })
        self.assertEqual(report["reason_combinations"], {
            "ALL_DECLARED_CHECKS_PASSED": 500,
            "DELIVERY_GPS_OUTSIDE_LIMIT": 100,
            "DELIVERY_PROOF_REFERENCE_MISSING": 100,
            "DESTINATION_IDENTITY_CONFLICT": 100,
            "PARCEL_IDENTITY_CONFLICT": 100,
            "TIMESTAMP_ORDER_CONFLICT": 100,
        })
        self.assertEqual(
            report["condition_reason_code_counts"]["gps_drift"],
            {"DELIVERY_GPS_OUTSIDE_LIMIT": 100},
        )

    def test_compound_report_fingerprints_every_pair_and_triple(self):
        report = benchmark(generate_compound_dataset(1200, seed=88))
        self.assertEqual(report["reason_code_counts"], {
            "ALL_DECLARED_CHECKS_PASSED": 400,
            "DELIVERY_GPS_OUTSIDE_LIMIT": 400,
            "DELIVERY_PROOF_REFERENCE_MISSING": 400,
            "DESTINATION_IDENTITY_CONFLICT": 400,
            "PARCEL_IDENTITY_CONFLICT": 400,
            "TIMESTAMP_ORDER_CONFLICT": 400,
        })
        self.assertEqual(report["reason_combinations"]["ALL_DECLARED_CHECKS_PASSED"], 400)
        self.assertEqual(len(report["reason_combinations"]), 21)
        self.assertEqual(
            sum(count for key, count in report["reason_combinations"].items()
                if key != "ALL_DECLARED_CHECKS_PASSED"),
            800,
        )
        for condition, counts in report["condition_reason_combinations"].items():
            if condition.startswith("compound:"):
                self.assertEqual(sum(counts.values()), 40)
                self.assertEqual(len(counts), 1)

    def test_single_anomaly_detection_matrix_maps_each_fault_to_its_invariant(self):
        report = benchmark(generate_dataset(1000, seed=88))
        expected = {
            "gps_drift": "DELIVERY_GPS_OUTSIDE_LIMIT",
            "wrong_parcel": "PARCEL_IDENTITY_CONFLICT",
            "wrong_destination": "DESTINATION_IDENTITY_CONFLICT",
            "reordered_events": "TIMESTAMP_ORDER_CONFLICT",
            "missing_proof": "DELIVERY_PROOF_REFERENCE_MISSING",
        }
        for anomaly, reason_code in expected.items():
            with self.subTest(anomaly=anomaly):
                detection = report["anomaly_detection"][anomaly]
                self.assertEqual(detection["expected_reason_code"], reason_code)
                self.assertEqual(detection["injected_occurrences"], 100)
                self.assertEqual(detection["detected_occurrences"], 100)
                self.assertEqual(detection["missed_occurrences"], 0)
                self.assertEqual(detection["detection_rate"], 1.0)
                self.assertEqual(
                    report["anomaly_reason_matrix"][anomaly],
                    {reason_code: 100},
                )
        self.assertEqual(report["clean_reason_code_counts"], {})

    def test_compound_detection_matrix_counts_each_injected_invariant(self):
        report = benchmark(generate_compound_dataset(1200, seed=88))
        for anomaly, detection in report["anomaly_detection"].items():
            with self.subTest(anomaly=anomaly):
                self.assertEqual(detection["injected_occurrences"], 400)
                self.assertEqual(detection["detected_occurrences"], 400)
                self.assertEqual(detection["missed_occurrences"], 0)
                self.assertEqual(detection["detection_rate"], 1.0)
                row = report["anomaly_reason_matrix"][anomaly]
                self.assertEqual(row[detection["expected_reason_code"]], 400)
                self.assertEqual(sum(row.values()), 400 + 4 * 160)
        self.assertEqual(report["clean_reason_code_counts"], {})

    def test_oracle_label_mismatch_is_visible_as_a_missed_invariant(self):
        journey = make_journey(31, "wrong_parcel")
        journey["injected_condition"] = "gps_drift"
        report = benchmark([journey])
        detection = report["anomaly_detection"]["gps_drift"]
        self.assertEqual(detection["injected_occurrences"], 1)
        self.assertEqual(detection["detected_occurrences"], 0)
        self.assertEqual(detection["missed_occurrences"], 1)
        self.assertEqual(
            report["anomaly_reason_matrix"]["gps_drift"],
            {"PARCEL_IDENTITY_CONFLICT": 1},
        )

    def test_sequence_echo_preserves_primary_detection_and_exposes_secondary_symptom(self):
        journey = make_interaction_journey(32, "reordered_events", "sequence_echo")
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("TIMESTAMP_ORDER_CONFLICT", result["reason_codes"])
        self.assertIn("EVENT_SEQUENCE_MISMATCH", result["reason_codes"])

        report = benchmark([journey])
        detection = report["anomaly_detection"]["reordered_events"]
        self.assertEqual(detection["detected_occurrences"], 1)
        self.assertEqual(detection["missed_occurrences"], 0)
        self.assertEqual(
            report["interaction_reason_combinations"]["sequence_echo"],
            {"EVENT_SEQUENCE_MISMATCH + TIMESTAMP_ORDER_CONFLICT": 1},
        )

    def test_missing_secondary_symptom_can_mask_primary_fault(self):
        journey = make_interaction_journey(
            33, "wrong_parcel", "missing_parcel_masks_conflict"
        )
        result = evaluate_journey(journey)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertIn("PARCEL_ID_MISSING_OR_INVALID", result["reason_codes"])
        self.assertNotIn("PARCEL_IDENTITY_CONFLICT", result["reason_codes"])

        report = benchmark([journey])
        detection = report["anomaly_detection"]["wrong_parcel"]
        self.assertEqual(detection["injected_occurrences"], 1)
        self.assertEqual(detection["detected_occurrences"], 0)
        self.assertEqual(detection["missed_occurrences"], 1)
        self.assertEqual(
            report["interaction_reason_combinations"]["missing_parcel_masks_conflict"],
            {"PARCEL_ID_MISSING_OR_INVALID": 1},
        )

    def test_diagnostic_trace_identifies_primary_and_secondary_symptoms(self):
        journey = make_interaction_journey(34, "reordered_events", "sequence_echo")
        report = benchmark([journey])
        trace = report["diagnostic_records"][0]
        self.assertEqual(trace["primary_fault"], "reordered_events")
        self.assertEqual(trace["expected_reason_code"], "TIMESTAMP_ORDER_CONFLICT")
        self.assertTrue(trace["primary_fault_detected"])
        self.assertEqual(trace["secondary_symptoms"], ["EVENT_SEQUENCE_MISMATCH"])
        self.assertEqual(trace["diagnostic_status"], "PRIMARY_IDENTIFIED_WITH_SYMPTOMS")

    def test_diagnostic_trace_marks_refusal_with_masked_primary(self):
        journey = make_interaction_journey(
            35, "wrong_parcel", "missing_parcel_masks_conflict"
        )
        report = benchmark([journey])
        trace = report["diagnostic_records"][0]
        self.assertEqual(trace["primary_fault"], "wrong_parcel")
        self.assertFalse(trace["primary_fault_detected"])
        self.assertEqual(trace["observed_reason_codes"], ["PARCEL_ID_MISSING_OR_INVALID"])
        self.assertEqual(trace["secondary_symptoms"], ["PARCEL_ID_MISSING_OR_INVALID"])
        self.assertEqual(trace["diagnostic_status"], "PRIMARY_MASKED")
        self.assertEqual(report["diagnostic_status_counts"], {"PRIMARY_MASKED": 1})

    def test_clean_and_compound_diagnostic_attribution_is_not_overstated(self):
        clean = make_journey(36)
        compound = make_compound_journey(37, ("gps_drift", "wrong_parcel"))
        report = benchmark([clean, compound])
        by_id = {record["journey_id"]: record for record in report["diagnostic_records"]}
        self.assertEqual(by_id["J-000036"]["diagnostic_status"], "CLEAN")
        self.assertIsNone(by_id["J-000036"]["primary_fault_detected"])
        self.assertEqual(by_id["J-000037"]["diagnostic_status"], "UNATTRIBUTED")
        self.assertIsNone(by_id["J-000037"]["primary_fault"])
        self.assertIsNone(by_id["J-000037"]["expected_reason_code"])

    def test_evaluator_output_is_invariant_to_oracle_metadata_changes(self):
        journeys = [
            make_journey(38, anomaly) for anomaly in ANOMALIES
        ]
        journeys.extend([
            make_compound_journey(39, ("gps_drift", "wrong_parcel")),
            make_interaction_journey(40, "wrong_parcel", "missing_parcel_masks_conflict"),
        ])
        for journey in journeys:
            with self.subTest(journey_id=journey["journey_id"]):
                relabelled = copy.deepcopy(journey)
                relabelled["injected_condition"] = "clean"
                relabelled["injected_interaction"] = "not-an-evaluator-input"
                self.assertEqual(
                    evaluate_journey(journey), evaluate_journey(relabelled)
                )

    def test_evaluator_does_not_consume_injected_oracle_label(self):
        journey = make_journey(30)
        journey["injected_condition"] = "compound:wrong_parcel+gps_drift"
        self.assertEqual(evaluate_journey(journey)["terminal_state"], "VERIFIED")

    def test_compound_generator_rejects_duplicate_anomalies(self):
        with self.assertRaises(ValueError):
            make_compound_journey(4, ("gps_drift", "gps_drift"))

    def test_invalid_dataset_size_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_dataset(999)


if __name__ == "__main__":
    unittest.main()
