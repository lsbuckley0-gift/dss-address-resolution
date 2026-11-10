"""Tests for the paired pilot metrics contract."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from experiments.pilot_metrics import evaluate


def decision(state, selected=None, complete=True, latency=None, review=None):
    return {"terminal_state": state, "selected_candidate_id": selected,
            "trace_complete": complete, "latency_ms": latency,
            "review_seconds": review, "review_routed": review is not None}


def pilot_data(cases):
    return {"dataset_id": "unit-test", "dataset_version": "v1", "cases": cases}


class PilotMetricsTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "dataset_id": "synthetic-check",
            "dataset_version": "v1",
            "cases": [
                {"case_id": "c1", "gold_candidate_id": "A",
                 "baseline": decision("VERIFIED", "A", latency=10),
                 "dss": decision("VERIFIED", "A", latency=12)},
                {"case_id": "c2", "gold_candidate_id": "B",
                 "baseline": decision("VERIFIED", "X", latency=20),
                 "dss": decision("UNRESOLVED", review=30)},
                {"case_id": "c3", "gold_candidate_id": None,
                 "baseline": decision("CORRECTED", "C"),
                 "dss": decision("UNRESOLVED", complete=False, review=50)},
            ],
        }

    def test_paired_metrics_have_explicit_denominators(self):
        report = evaluate(self.data)
        baseline = report["systems"]["baseline"]
        self.assertEqual(report["paired_case_count"], 3)
        self.assertEqual(baseline["false_accepts"], 2)
        self.assertEqual(baseline["auto_resolved"], 3)
        self.assertEqual(baseline["false_rejects"], 0)
        self.assertEqual(baseline["unique_gold_cases"], 2)
        self.assertEqual(baseline["correct_abstentions"], 0)
        self.assertAlmostEqual(baseline["false_accept_rate"], 2 / 3)
        self.assertAlmostEqual(baseline["false_accept_prevalence"], 2 / 3)
        self.assertEqual(baseline["corrections"], 1)
        self.assertEqual(baseline["correct_corrections"], 0)
        self.assertEqual(baseline["latency_p95_ms_nearest_rank"], 20)
        self.assertEqual(report["systems"]["dss"]["unresolved"], 2)
        self.assertEqual(report["systems"]["dss"]["median_review_seconds"], 40)
        self.assertEqual(report["systems"]["dss"]["review_routed_cases"], 2)
        self.assertEqual(report["systems"]["dss"]["review_time_measurement_coverage"], 1.0)

    def test_zero_acceptances_has_null_rate_and_interval(self):
        data = pilot_data([
            {"case_id": "c1", "gold_candidate_id": "A",
             "baseline": decision("UNRESOLVED"),
             "dss": decision("UNRESOLVED")}
        ])
        metrics = evaluate(data)["systems"]["dss"]
        self.assertIsNone(metrics["false_accept_rate"])
        self.assertIsNone(metrics["false_accept_rate_95pct_wilson"])
        self.assertEqual(metrics["false_rejects"], 1)
        self.assertEqual(metrics["false_reject_rate"], 1.0)
        self.assertEqual(metrics["correct_abstentions"], 0)



    def test_input_schema_declares_required_provenance_and_pair(self):
        repo_root = Path(__file__).resolve().parents[1]
        schema_path = repo_root / "experiments" / "schemas" / "paired-pilot-input-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["required"], ["dataset_id", "dataset_version", "cases"])
        self.assertEqual(
            schema["$defs"]["case"]["required"],
            ["case_id", "gold_candidate_id", "baseline", "dss"],
        )
        self.assertIn("stratum", schema["$defs"]["case"]["properties"])
        self.assertIn("UNSPECIFIED", schema["$defs"]["case"]["properties"]["stratum"]["enum"])
        requirements = schema["properties"]["sample_requirements"]
        self.assertEqual(
            requirements["required"],
            ["required_strata", "minimum_case_count", "minimum_unique_gold_case_count"],
        )
        self.assertTrue(requirements["properties"]["required_strata"]["uniqueItems"])
        self.assertEqual(requirements["properties"]["minimum_case_count"]["minimum"], 1)
        self.assertEqual(requirements["properties"]["minimum_unique_gold_case_count"]["minimum"], 1)
        decision_requirements = schema["properties"]["decision_requirements"]
        self.assertEqual(decision_requirements["required"], [
            "system", "max_false_accept_rate_upper_95pct",
            "max_false_reject_rate_upper_95pct", "minimum_coverage",
            "maximum_review_routed_rate", "maximum_median_review_seconds",
            "minimum_review_time_measurement_coverage",
        ])
        self.assertEqual(decision_requirements["properties"]["minimum_coverage"]["maximum"], 1)

    def test_dataset_provenance_is_required(self):
        with self.assertRaisesRegex(ValueError, "dataset_id must be a non-empty string"):
            evaluate({"cases": self.data["cases"]})
        with self.assertRaisesRegex(ValueError, "dataset_version must be a non-empty string"):
            evaluate({"dataset_id": "dataset", "cases": self.data["cases"]})

    def test_missing_gold_label_is_rejected_instead_of_treated_as_ambiguous(self):
        data = pilot_data([
            {"case_id": "c1",
             "baseline": decision("UNRESOLVED"),
             "dss": decision("UNRESOLVED")}
        ])
        with self.assertRaisesRegex(ValueError, "gold_candidate_id is required"):
            evaluate(data)


    def test_empty_evaluation_set_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one paired case"):
            evaluate(pilot_data([]))

    def test_non_boolean_trace_completeness_is_rejected(self):
        data = pilot_data([
            {"case_id": "c1", "gold_candidate_id": "A",
             "baseline": decision("VERIFIED", "A"),
             "dss": decision("VERIFIED", "A", complete=1)}
        ])
        with self.assertRaisesRegex(ValueError, "trace_complete must be boolean"):
            evaluate(data)

    def test_review_time_requires_explicit_review_routing(self):
        data = pilot_data([
            {"case_id": "c1", "gold_candidate_id": "A",
             "baseline": dict(decision("UNRESOLVED", review=12), review_routed=False),
             "dss": decision("UNRESOLVED")}
        ])
        with self.assertRaisesRegex(ValueError, "review_seconds requires review_routed=true"):
            evaluate(data)

    def test_only_unresolved_cases_can_be_routed_to_review(self):
        data = pilot_data([
            {"case_id": "c1", "gold_candidate_id": "A",
             "baseline": decision("VERIFIED", "A"),
             "dss": dict(decision("VERIFIED", "A"), review_routed=True)}
        ])
        with self.assertRaisesRegex(ValueError, "only unresolved cases"):
            evaluate(data)

    def test_duplicate_case_ids_are_rejected(self):
        case = self.data["cases"][0]
        duplicate = dict(case)
        with self.assertRaisesRegex(ValueError, "Duplicate case_id"):
            evaluate(pilot_data([case, duplicate]))

    def test_unresolved_cannot_claim_selected_candidate(self):
        data = pilot_data([
            {"case_id": "c1", "gold_candidate_id": "A",
             "baseline": decision("UNRESOLVED", "A"),
             "dss": decision("UNRESOLVED")}
        ])
        with self.assertRaisesRegex(ValueError, "UNRESOLVED must not select"):
            evaluate(data)

    def test_accepted_case_requires_candidate_and_boolean_trace_flag(self):
        data = pilot_data([
            {"case_id": "c1", "gold_candidate_id": "A",
             "baseline": decision("VERIFIED"),
             "dss": decision("VERIFIED", "A")}
        ])
        with self.assertRaisesRegex(ValueError, "require a selected candidate"):
            evaluate(data)


    def test_synthetic_fixture_runs_through_cli_end_to_end(self):
        repo_root = Path(__file__).resolve().parents[1]
        fixture = repo_root / "experiments" / "fixtures" / "paired-pilot-synthetic-v1.json"
        script = repo_root / "experiments" / "pilot_metrics.py"
        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "pilot-report.json"
            completed = subprocess.run(
                [sys.executable, str(script), str(fixture), "--json-out", str(output_path)],
                cwd=repo_root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, msg=completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), report)
        self.assertEqual(report["dataset_id"], "paired-pilot-synthetic")
        self.assertEqual(report["report_version"], "paired-pilot-metrics/1.9")
        self.assertEqual(report["case_count"], 4)
        self.assertEqual(set(report["stratum_metrics"]), {"EXACT", "TYPO", "FORMATTING_ONLY", "CONFLICTING"})
        self.assertEqual(report["stratum_metrics"]["TYPO"]["case_count"], 1)
        self.assertEqual(
            sum(sum(row.values()) for row in report["stratum_metrics"]["TYPO"]["paired_outcome_matrix"].values()),
            1,
        )
        matrix = report["paired_outcome_matrix"]
        self.assertEqual(sum(sum(row.values()) for row in matrix.values()), 4)
        self.assertEqual(
            matrix["CORRECT_AUTO_RESOLUTION"]["CORRECT_AUTO_RESOLUTION"], 1
        )
        self.assertEqual(matrix["FALSE_ACCEPT"]["FALSE_REJECT"], 1)
        self.assertEqual(matrix["FALSE_ACCEPT"]["CORRECT_ABSTENTION"], 1)
        self.assertEqual(matrix["FALSE_REJECT"]["CORRECT_AUTO_RESOLUTION"], 1)

        baseline = report["systems"]["baseline"]
        self.assertEqual(baseline["false_accepts"], 2)
        self.assertAlmostEqual(baseline["false_accept_rate"], 2 / 3)
        self.assertAlmostEqual(baseline["false_accept_prevalence"], 0.5)
        self.assertEqual(baseline["false_rejects"], 1)
        self.assertAlmostEqual(baseline["false_reject_rate"], 1 / 3)
        self.assertAlmostEqual(baseline["false_reject_prevalence"], 0.25)
        self.assertEqual(baseline["correct_abstentions"], 0)

        dss = report["systems"]["dss"]
        self.assertEqual(dss["false_accepts"], 0)
        self.assertEqual(dss["false_rejects"], 1)
        self.assertAlmostEqual(dss["false_reject_rate"], 1 / 3)
        self.assertAlmostEqual(dss["false_reject_prevalence"], 0.25)
        self.assertEqual(dss["correct_abstentions"], 1)
        self.assertEqual(dss["correct_corrections"], 1)
        self.assertEqual(dss["review_routed_cases"], 2)
        self.assertEqual(dss["review_cases_with_time"], 2)
        self.assertEqual(dss["median_review_seconds"], 45)
        self.assertEqual(dss["latency_p95_ms_nearest_rank"], 19)




    def test_paired_outcome_matrix_partitions_every_case_once(self):
        report = evaluate(self.data)
        matrix = report["paired_outcome_matrix"]
        self.assertEqual(sum(sum(row.values()) for row in matrix.values()), 3)
        self.assertEqual(
            matrix["CORRECT_AUTO_RESOLUTION"]["CORRECT_AUTO_RESOLUTION"], 1
        )
        self.assertEqual(matrix["FALSE_ACCEPT"]["FALSE_REJECT"], 1)
        self.assertEqual(matrix["FALSE_ACCEPT"]["CORRECT_ABSTENTION"], 1)

    def test_paired_class_comparisons_report_exact_discordance_and_direction(self):
        report = evaluate(self.data)
        comparisons = report["paired_class_comparisons"]["outcomes"]
        false_accept = comparisons["FALSE_ACCEPT"]
        self.assertEqual(false_accept["case_count"], 3)
        self.assertEqual(false_accept["baseline_only"], 2)
        self.assertEqual(false_accept["dss_only"], 0)
        self.assertEqual(false_accept["baseline_and_dss"], 0)
        self.assertEqual(false_accept["neither"], 1)
        self.assertEqual(false_accept["discordant_case_count"], 2)
        self.assertAlmostEqual(
            false_accept["prevalence_difference_dss_minus_baseline"], -2 / 3
        )
        self.assertEqual(false_accept["exact_mcnemar_p_value_two_sided"], 0.5)
        self.assertEqual(
            comparisons["FALSE_REJECT"]["exact_mcnemar_p_value_two_sided"], 1.0
        )
        self.assertEqual(
            report["stratum_metrics"]["UNSPECIFIED"]["paired_class_comparisons"]["outcomes"]["FALSE_ACCEPT"]["baseline_only"],
            2,
        )

    def test_exact_mcnemar_probability_for_six_one_directional_discordances(self):
        cases = []
        for index in range(6):
            cases.append({
                "case_id": "ambiguous-" + str(index),
                "gold_candidate_id": None,
                "baseline": decision("VERIFIED", "wrong-" + str(index)),
                "dss": decision("UNRESOLVED"),
            })
        comparisons = evaluate(pilot_data(cases))["paired_class_comparisons"]["outcomes"]
        false_accept = comparisons["FALSE_ACCEPT"]
        self.assertEqual(false_accept["baseline_only"], 6)
        self.assertEqual(false_accept["dss_only"], 0)
        self.assertAlmostEqual(
            false_accept["exact_mcnemar_p_value_two_sided"], 0.03125
        )

    def test_paired_class_comparison_partitions_each_stratum(self):
        report = evaluate(self.data)
        for stratum in report["stratum_metrics"].values():
            for comparison in stratum["paired_class_comparisons"]["outcomes"].values():
                self.assertEqual(
                    comparison["baseline_and_dss"]
                    + comparison["baseline_only"]
                    + comparison["dss_only"]
                    + comparison["neither"],
                    stratum["case_count"],
                )

    def test_false_reject_rate_is_null_without_unique_gold_cases(self):
        data = pilot_data([
            {"case_id": "ambiguous", "gold_candidate_id": None,
             "baseline": decision("UNRESOLVED"),
             "dss": decision("UNRESOLVED")}
        ])
        metrics = evaluate(data)["systems"]["dss"]
        self.assertEqual(metrics["false_rejects"], 0)
        self.assertIsNone(metrics["false_reject_rate"])
        self.assertIsNone(metrics["false_reject_rate_95pct_wilson"])
        self.assertEqual(metrics["correct_abstentions"], 1)

    def test_undeclared_fields_are_rejected_at_every_input_level(self):
        mutations = (
            (
                "input",
                lambda data: data.update({"raw_address": "fictional value"}),
                "input contains unsupported field",
            ),
            (
                "case",
                lambda data: data["cases"][0].update({"address": "fictional value"}),
                r"cases\[0\] contains unsupported field",
            ),
            (
                "decision",
                lambda data: data["cases"][0]["dss"].update({"postcode": "ZZ1 1ZZ"}),
                r"cases\[0\]\.dss contains unsupported field",
            ),
        )
        for level, mutate, message in mutations:
            with self.subTest(level=level):
                data = json.loads(json.dumps(self.data))
                mutate(data)
                with self.assertRaisesRegex(ValueError, message):
                    evaluate(data)


    def test_stratum_metrics_partition_cases_and_preserve_paired_denominators(self):
        data = pilot_data([
            {"case_id": "exact", "gold_candidate_id": "A", "stratum": "EXACT",
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")},
            {"case_id": "typo", "gold_candidate_id": "B", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "X"), "dss": decision("UNRESOLVED")},
            {"case_id": "ambiguous", "gold_candidate_id": None, "stratum": "CONFLICTING",
             "baseline": decision("UNRESOLVED"), "dss": decision("UNRESOLVED")},
        ])
        report = evaluate(data)
        strata = report["stratum_metrics"]
        self.assertEqual(sum(item["case_count"] for item in strata.values()), 3)
        self.assertEqual(strata["TYPO"]["systems"]["dss"]["unique_gold_cases"], 1)
        self.assertEqual(strata["TYPO"]["systems"]["dss"]["false_reject_rate"], 1.0)
        self.assertIsNone(strata["CONFLICTING"]["systems"]["dss"]["false_reject_rate"])
        self.assertEqual(
            sum(sum(row.values()) for row in strata["EXACT"]["paired_outcome_matrix"].values()), 1
        )


    def test_non_string_stratum_is_rejected(self):
        data = pilot_data([
            {"case_id": "bad-stratum", "gold_candidate_id": "A", "stratum": ["TYPO"],
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")}
        ])
        with self.assertRaisesRegex(ValueError, "stratum must be one of"):
            evaluate(data)

    def test_missing_stratum_is_explicitly_grouped_as_unspecified(self):
        report = evaluate(pilot_data([
            {"case_id": "unlabelled", "gold_candidate_id": "A",
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")}
        ]))
        self.assertEqual(report["stratum_metrics"]["UNSPECIFIED"]["case_count"], 1)


    def test_stratum_matrices_recompose_global_paired_matrix_exactly(self):
        report = evaluate(self.data)
        global_matrix = report["paired_outcome_matrix"]
        strata = report["stratum_metrics"]
        for baseline_class in global_matrix:
            for dss_class in global_matrix[baseline_class]:
                stratum_total = sum(
                    item["paired_outcome_matrix"][baseline_class][dss_class]
                    for item in strata.values()
                )
                self.assertEqual(
                    stratum_total,
                    global_matrix[baseline_class][dss_class],
                    msg=f"stratum decomposition lost transition {baseline_class} -> {dss_class}",
                )

    def test_unknown_stratum_is_rejected(self):
        data = pilot_data([
            {"case_id": "unknown", "gold_candidate_id": "A", "stratum": "NEAR_ENOUGH",
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")}
        ])
        with self.assertRaisesRegex(ValueError, "stratum must be one of"):
            evaluate(data)

    def test_whitespace_only_provenance_is_rejected(self):
        data = json.loads(json.dumps(self.data))
        data["dataset_id"] = "   "
        with self.assertRaisesRegex(ValueError, "dataset_id must be a non-empty string"):
            evaluate(data)

    def test_sample_sufficiency_reports_missing_and_below_minimum_strata(self):
        data = pilot_data([
            {"case_id": "one", "gold_candidate_id": "A", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")},
            {"case_id": "two", "gold_candidate_id": None, "stratum": "TYPO",
             "baseline": decision("UNRESOLVED"), "dss": decision("UNRESOLVED")},
        ])
        data["sample_requirements"] = {
            "required_strata": ["TYPO", "DUPLICATE"],
            "minimum_case_count": 3,
            "minimum_unique_gold_case_count": 2,
        }
        gate = evaluate(data)["sample_sufficiency"]
        self.assertEqual(gate["status"], "INSUFFICIENT")
        self.assertEqual(gate["strata"]["TYPO"]["status"], "BELOW_MINIMUM")
        self.assertEqual(gate["strata"]["TYPO"]["case_count"], 2)
        self.assertEqual(gate["strata"]["TYPO"]["unique_gold_case_count"], 1)
        self.assertEqual(gate["strata"]["DUPLICATE"]["status"], "MISSING")
        self.assertIn("does not establish representative sampling", gate["interpretation"])

    def test_sample_sufficiency_passes_only_when_both_count_thresholds_are_met(self):
        data = pilot_data([
            {"case_id": "typo-1", "gold_candidate_id": "G-1", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "G-1"), "dss": decision("VERIFIED", "G-1")},
            {"case_id": "typo-2", "gold_candidate_id": "G-2", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "G-2"), "dss": decision("VERIFIED", "G-2")},
            {"case_id": "typo-3", "gold_candidate_id": "G-3", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "G-3"), "dss": decision("VERIFIED", "G-3")},
        ])
        data["sample_requirements"] = {
            "required_strata": ["TYPO"],
            "minimum_case_count": 3,
            "minimum_unique_gold_case_count": 3,
        }
        gate = evaluate(data)["sample_sufficiency"]
        self.assertEqual(gate["status"], "SUFFICIENT")
        self.assertEqual(gate["strata"]["TYPO"]["status"], "SUFFICIENT")

    def test_sample_sufficiency_is_explicitly_not_configured_by_default(self):
        gate = evaluate(self.data)["sample_sufficiency"]
        self.assertEqual(gate["status"], "NOT_CONFIGURED")
        self.assertIsNone(gate["requirements"])

    def test_sample_requirements_reject_duplicate_or_invalid_strata(self):
        for labels in (["TYPO", "TYPO"], ["UNSPECIFIED"], ["TYPO", 7]):
            with self.subTest(labels=labels):
                data = json.loads(json.dumps(self.data))
                data["sample_requirements"] = {
                    "required_strata": labels, "minimum_case_count": 2,
                    "minimum_unique_gold_case_count": 1,
                }
                with self.assertRaisesRegex(ValueError, "required_strata"):
                    evaluate(data)

    def test_sample_requirements_reject_non_positive_or_boolean_minima(self):
        for minimum in (0, -1, True, 1.5):
            with self.subTest(minimum=minimum):
                data = json.loads(json.dumps(self.data))
                data["sample_requirements"] = {
                    "required_strata": ["TYPO"], "minimum_case_count": minimum,
                    "minimum_unique_gold_case_count": 1,
                }
                with self.assertRaisesRegex(ValueError, "minimum_case_count must be a positive integer"):
                    evaluate(data)

    def test_sample_gate_fails_closed_when_any_case_is_unclassified(self):
        data = pilot_data([
            {"case_id": "classified", "gold_candidate_id": "A", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")},
            {"case_id": "unclassified", "gold_candidate_id": "B",
             "baseline": decision("VERIFIED", "B"), "dss": decision("VERIFIED", "B")},
        ])
        data["sample_requirements"] = {
            "required_strata": ["TYPO"], "minimum_case_count": 1,
            "minimum_unique_gold_case_count": 1,
        }
        gate = evaluate(data)["sample_sufficiency"]
        self.assertEqual(gate["strata"]["TYPO"]["status"], "SUFFICIENT")
        self.assertEqual(gate["unclassified_case_count"], 1)
        self.assertEqual(gate["status"], "INSUFFICIENT")

    def test_sample_gate_fails_when_an_observed_stratum_is_not_pre_registered(self):
        data = pilot_data([
            {"case_id": "typo", "gold_candidate_id": "A", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")},
            {"case_id": "format", "gold_candidate_id": "B", "stratum": "FORMATTING_ONLY",
             "baseline": decision("VERIFIED", "B"), "dss": decision("VERIFIED", "B")},
        ])
        data["sample_requirements"] = {
            "required_strata": ["TYPO"], "minimum_case_count": 1,
            "minimum_unique_gold_case_count": 1,
        }
        gate = evaluate(data)["sample_sufficiency"]
        self.assertEqual(gate["strata"]["TYPO"]["status"], "SUFFICIENT")
        self.assertEqual(gate["unassessed_strata"], ["FORMATTING_ONLY"])
        self.assertEqual(gate["status"], "INSUFFICIENT")

    def test_decision_assessment_passes_only_when_all_preregistered_limits_pass(self):
        data = pilot_data([
            {"case_id": "a", "gold_candidate_id": "A",
             "baseline": decision("VERIFIED", "A", review=None),
             "dss": decision("VERIFIED", "A")},
            {"case_id": "b", "gold_candidate_id": "B",
             "baseline": decision("VERIFIED", "B"),
             "dss": decision("UNRESOLVED", review=20)},
            {"case_id": "c", "gold_candidate_id": None,
             "baseline": decision("UNRESOLVED"),
             "dss": decision("UNRESOLVED", review=40)},
        ])
        data["decision_requirements"] = {
            "system": "dss",
            "max_false_accept_rate_upper_95pct": 1.0,
            "max_false_reject_rate_upper_95pct": 1.0,
            "minimum_coverage": 0.0,
            "maximum_review_routed_rate": 1.0,
            "maximum_median_review_seconds": 60,
            "minimum_review_time_measurement_coverage": 1.0,
        }
        assessment = evaluate(data)["decision_assessment"]
        self.assertEqual(assessment["status"], "PASS", assessment["criteria"])
        self.assertGreater(assessment["criteria"]["false_accept_rate_upper_95pct"]["observed"], 0.0)

    def test_decision_assessment_uses_upper_wilson_bound_not_point_rate(self):
        data = pilot_data([
            {"case_id": "only", "gold_candidate_id": "A",
             "baseline": decision("VERIFIED", "A"),
             "dss": decision("VERIFIED", "WRONG")},
        ])
        data["decision_requirements"] = {
            "system": "dss", "max_false_accept_rate_upper_95pct": 0.5,
            "max_false_reject_rate_upper_95pct": 1.0, "minimum_coverage": 0.0,
            "maximum_review_routed_rate": 1.0, "maximum_median_review_seconds": 60,
            "minimum_review_time_measurement_coverage": 0.0,
        }
        assessment = evaluate(data)["decision_assessment"]
        criterion = assessment["criteria"]["false_accept_rate_upper_95pct"]
        self.assertEqual(criterion["status"], "FAIL")
        self.assertGreater(criterion["observed"], 0.5)

    def test_decision_assessment_is_indeterminate_when_error_denominator_missing(self):
        data = pilot_data([
            {"case_id": "ambiguous", "gold_candidate_id": None,
             "baseline": decision("UNRESOLVED"), "dss": decision("UNRESOLVED")},
        ])
        data["decision_requirements"] = {
            "system": "dss", "max_false_accept_rate_upper_95pct": 0.1,
            "max_false_reject_rate_upper_95pct": 0.1, "minimum_coverage": 0.0,
            "maximum_review_routed_rate": 1.0, "maximum_median_review_seconds": 60,
            "minimum_review_time_measurement_coverage": 0.0,
        }
        assessment = evaluate(data)["decision_assessment"]
        self.assertEqual(assessment["status"], "INDETERMINATE")
        self.assertEqual(assessment["criteria"]["false_reject_rate_upper_95pct"]["status"], "INDETERMINATE")

    def test_decision_assessment_is_indeterminate_when_routed_review_time_is_missing(self):
        data = pilot_data([
            {"case_id": "known", "gold_candidate_id": "A",
             "baseline": decision("UNRESOLVED"),
             "dss": {"terminal_state": "UNRESOLVED", "selected_candidate_id": None,
                     "trace_complete": True, "review_routed": True}},
        ])
        data["decision_requirements"] = {
            "system": "dss", "max_false_accept_rate_upper_95pct": 1.0,
            "max_false_reject_rate_upper_95pct": 1.0, "minimum_coverage": 0.0,
            "maximum_review_routed_rate": 1.0, "maximum_median_review_seconds": 60,
            "minimum_review_time_measurement_coverage": 0.0,
        }
        assessment = evaluate(data)["decision_assessment"]
        self.assertEqual(assessment["status"], "INDETERMINATE", assessment["criteria"])
        self.assertEqual(assessment["criteria"]["median_review_seconds"]["status"], "INDETERMINATE")

    def test_decision_requirements_reject_out_of_range_or_boolean_thresholds(self):
        data = json.loads(json.dumps(self.data))
        data["decision_requirements"] = {
            "system": "dss", "max_false_accept_rate_upper_95pct": 1.1,
            "max_false_reject_rate_upper_95pct": 1.0, "minimum_coverage": 0.0,
            "maximum_review_routed_rate": 1.0, "maximum_median_review_seconds": 60,
            "minimum_review_time_measurement_coverage": 1.0,
        }
        with self.assertRaisesRegex(ValueError, "max_false_accept_rate_upper_95pct"):
            evaluate(data)

    def test_decision_assessment_is_not_configured_without_preregistered_thresholds(self):
        assessment = evaluate(self.data)["decision_assessment"]
        self.assertEqual(assessment["status"], "NOT_CONFIGURED")
        self.assertEqual(assessment["criteria"], {})

    def test_decision_assessment_marks_review_time_not_applicable_when_no_review_is_routed(self):
        data = pilot_data([
            {"case_id": "known", "gold_candidate_id": "A",
             "baseline": decision("VERIFIED", "A"),
             "dss": decision("VERIFIED", "A")},
        ])
        data["decision_requirements"] = {
            "system": "dss", "max_false_accept_rate_upper_95pct": 1.0,
            "max_false_reject_rate_upper_95pct": 1.0, "minimum_coverage": 1.0,
            "maximum_review_routed_rate": 0.0, "maximum_median_review_seconds": 60,
            "minimum_review_time_measurement_coverage": 1.0,
        }
        assessment = evaluate(data)["decision_assessment"]
        self.assertEqual(assessment["status"], "PASS")
        self.assertEqual(assessment["criteria"]["median_review_seconds"]["status"], "NOT_APPLICABLE")
        self.assertEqual(assessment["criteria"]["review_time_measurement_coverage"]["status"], "NOT_APPLICABLE")

    def test_decision_assessment_enforces_coverage_and_review_routing_limits(self):
        data = pilot_data([
            {"case_id": "accepted", "gold_candidate_id": "A",
             "baseline": decision("VERIFIED", "A"),
             "dss": decision("VERIFIED", "A")},
            {"case_id": "reviewed", "gold_candidate_id": "B",
             "baseline": decision("VERIFIED", "B"),
             "dss": decision("UNRESOLVED", review=15)},
        ])
        data["decision_requirements"] = {
            "system": "dss", "max_false_accept_rate_upper_95pct": 1.0,
            "max_false_reject_rate_upper_95pct": 1.0, "minimum_coverage": 0.75,
            "maximum_review_routed_rate": 0.25, "maximum_median_review_seconds": 30,
            "minimum_review_time_measurement_coverage": 1.0,
        }
        assessment = evaluate(data)["decision_assessment"]
        self.assertEqual(assessment["criteria"]["coverage"]["observed"], 0.5)
        self.assertEqual(assessment["criteria"]["coverage"]["status"], "FAIL")
        self.assertEqual(assessment["criteria"]["review_routed_rate"]["observed"], 0.5)
        self.assertEqual(assessment["criteria"]["review_routed_rate"]["status"], "FAIL")
        self.assertEqual(assessment["status"], "FAIL")

    def test_pilot_readiness_passes_only_when_both_configured_gates_pass(self):
        data = pilot_data([
            {"case_id": "a", "gold_candidate_id": "A", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")},
            {"case_id": "b", "gold_candidate_id": "B", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "B"), "dss": decision("VERIFIED", "B")},
        ])
        data["sample_requirements"] = {
            "required_strata": ["TYPO"], "minimum_case_count": 2,
            "minimum_unique_gold_case_count": 2,
        }
        data["decision_requirements"] = {
            "system": "dss", "max_false_accept_rate_upper_95pct": 1.0,
            "max_false_reject_rate_upper_95pct": 1.0, "minimum_coverage": 1.0,
            "maximum_review_routed_rate": 0.0, "maximum_median_review_seconds": 0,
            "minimum_review_time_measurement_coverage": 1.0,
        }
        report = evaluate(data)
        self.assertEqual(report["sample_sufficiency"]["status"], "SUFFICIENT")
        self.assertEqual(report["decision_assessment"]["status"], "PASS")
        self.assertEqual(report["pilot_readiness"]["status"], "PASS")

    def test_pilot_readiness_fails_if_either_configured_gate_fails(self):
        data = pilot_data([
            {"case_id": "a", "gold_candidate_id": "A", "stratum": "TYPO",
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")},
        ])
        data["sample_requirements"] = {
            "required_strata": ["TYPO"], "minimum_case_count": 2,
            "minimum_unique_gold_case_count": 1,
        }
        report = evaluate(data)
        self.assertEqual(report["sample_sufficiency"]["status"], "INSUFFICIENT")
        self.assertEqual(report["pilot_readiness"]["status"], "FAIL")

    def test_pilot_readiness_is_indeterminate_when_one_gate_is_not_configured(self):
        data = pilot_data([
            {"case_id": "a", "gold_candidate_id": "A",
             "baseline": decision("VERIFIED", "A"), "dss": decision("VERIFIED", "A")},
        ])
        data["decision_requirements"] = {
            "system": "dss", "max_false_accept_rate_upper_95pct": 1.0,
            "max_false_reject_rate_upper_95pct": 1.0, "minimum_coverage": 1.0,
            "maximum_review_routed_rate": 0.0, "maximum_median_review_seconds": 0,
            "minimum_review_time_measurement_coverage": 1.0,
        }
        report = evaluate(data)
        self.assertEqual(report["decision_assessment"]["status"], "PASS")
        self.assertEqual(report["sample_sufficiency"]["status"], "NOT_CONFIGURED")
        self.assertEqual(report["pilot_readiness"]["status"], "INDETERMINATE")

    def test_pilot_readiness_is_not_configured_when_both_gates_are_absent(self):
        readiness = evaluate(self.data)["pilot_readiness"]
        self.assertEqual(readiness["status"], "NOT_CONFIGURED")

if __name__ == "__main__":
    unittest.main()
