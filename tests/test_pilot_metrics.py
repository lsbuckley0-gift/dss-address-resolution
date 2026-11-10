"""Tests for the paired pilot metrics contract."""
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from experiments.pilot_metrics import (evaluate, _exact_mcnemar_p_value, _clopper_pearson, _paired_prevalence_difference_interval, _primary_endpoint_spec_sha256)
from experiments.registration_evidence import verify_registration_evidence
from experiments.audit_event_chain import append_audit_event, verify_event_chain, verify_external_checkpoint


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
        primary_endpoint = schema["properties"]["primary_endpoint"]
        self.assertEqual(primary_endpoint["required"], [
            "outcome_class", "expected_direction", "analysis_population", "alpha",
            "registration_reference", "frozen_before_outcomes_review",
        ])
        self.assertEqual(primary_endpoint["properties"]["analysis_population"]["const"], "ALL_PAIRED_CASES")
        self.assertEqual(primary_endpoint["properties"]["frozen_before_outcomes_review"]["const"], True)
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
        self.assertEqual(report["report_version"], "paired-pilot-metrics/2.1")
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
            false_accept["holm_adjusted_p_value_within_four_outcome_family"], 1.0
        )
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
        self.assertAlmostEqual(
            false_accept["holm_adjusted_p_value_within_four_outcome_family"], 0.125
        )
        self.assertAlmostEqual(
            comparisons["CORRECT_ABSTENTION"]["holm_adjusted_p_value_within_four_outcome_family"],
            0.125,
        )

    def test_clopper_pearson_exact_boundary_cases_and_symmetry(self):
        zero = _clopper_pearson(0, 1, confidence=0.975)
        one = _clopper_pearson(1, 1, confidence=0.975)
        self.assertEqual(zero[0], 0.0)
        self.assertAlmostEqual(zero[1], 0.9875, places=10)
        self.assertAlmostEqual(one[0], 0.0125, places=10)
        self.assertEqual(one[1], 1.0)
        interval = _clopper_pearson(2, 5, confidence=0.975)
        reflected = _clopper_pearson(3, 5, confidence=0.975)
        self.assertAlmostEqual(interval[0], 1.0 - reflected[1], places=10)
        self.assertAlmostEqual(interval[1], 1.0 - reflected[0], places=10)

    def test_paired_prevalence_difference_interval_contains_estimate(self):
        interval = _paired_prevalence_difference_interval(2, 5, 20)
        estimate = (5 - 2) / 20
        self.assertLessEqual(interval[0], estimate)
        self.assertGreaterEqual(interval[1], estimate)
        self.assertGreaterEqual(interval[0], -1.0)
        self.assertLessEqual(interval[1], 1.0)

    def test_no_observed_discordances_still_has_uncertainty_interval(self):
        interval = _paired_prevalence_difference_interval(0, 0, 1)
        self.assertAlmostEqual(interval[0], -0.9875, places=10)
        self.assertAlmostEqual(interval[1], 0.9875, places=10)

    def test_more_stringent_primary_alpha_widens_conservative_interval(self):
        standard = _paired_prevalence_difference_interval(2, 5, 20, alpha=0.05)
        stringent = _paired_prevalence_difference_interval(2, 5, 20, alpha=0.01)
        self.assertGreaterEqual(
            stringent[1] - stringent[0],
            standard[1] - standard[0],
        )

    def test_paired_confidence_interval_is_directionally_symmetric(self):
        forward = _paired_prevalence_difference_interval(1, 6, 20)
        reverse = _paired_prevalence_difference_interval(6, 1, 20)
        self.assertAlmostEqual(forward[0], -reverse[1], places=10)
        self.assertAlmostEqual(forward[1], -reverse[0], places=10)

    def test_primary_endpoint_supports_preregistered_direction_when_interval_excludes_zero(self):
        cases = [{
            "case_id": "case-" + str(index),
            "gold_candidate_id": None,
            "baseline": decision("VERIFIED", "wrong-" + str(index)),
            "dss": decision("UNRESOLVED"),
        } for index in range(20)]
        data = pilot_data(cases)
        data["primary_endpoint"] = {
            "outcome_class": "FALSE_ACCEPT",
            "expected_direction": "LOWER",
            "analysis_population": "ALL_PAIRED_CASES",
            "alpha": 0.05,
            "registration_reference": "protocol-v1-section-4",
            "frozen_before_outcomes_review": True,
        }
        report = evaluate(data)
        assessment = report["primary_endpoint_assessment"]
        self.assertEqual(assessment["status"], "SUPPORTS_DIRECTION")
        self.assertLess(assessment["endpoint"]["prevalence_difference_confidence_interval"][1], 0)
        self.assertTrue(assessment["endpoint"]["two_sided_mcnemar_p_value_at_or_below_alpha"])
        self.assertEqual(assessment["endpoint"]["case_count"], 20)
        self.assertEqual(len(assessment["endpoint"]["endpoint_spec_sha256"]), 64)
        self.assertIn("not independently verified", assessment["interpretation"])

    def test_primary_endpoint_is_indeterminate_when_interval_crosses_zero(self):
        data = pilot_data([{
            "case_id": "case-0",
            "gold_candidate_id": None,
            "baseline": decision("VERIFIED", "wrong"),
            "dss": decision("UNRESOLVED"),
        }])
        data["primary_endpoint"] = {
            "outcome_class": "FALSE_ACCEPT", "expected_direction": "LOWER",
            "analysis_population": "ALL_PAIRED_CASES", "alpha": 0.05,
            "registration_reference": "protocol-v1", "frozen_before_outcomes_review": True,
        }
        self.assertEqual(evaluate(data)["primary_endpoint_assessment"]["status"], "INDETERMINATE")

    def test_primary_endpoint_reports_opposite_direction_without_rewriting_hypothesis(self):
        data = pilot_data([{
            "case_id": "case-" + str(index),
            "gold_candidate_id": None,
            "baseline": decision("UNRESOLVED"),
            "dss": decision("VERIFIED", "wrong-" + str(index)),
        } for index in range(20)])
        data["primary_endpoint"] = {
            "outcome_class": "FALSE_ACCEPT", "expected_direction": "LOWER",
            "analysis_population": "ALL_PAIRED_CASES", "alpha": 0.05,
            "registration_reference": "protocol-v1", "frozen_before_outcomes_review": True,
        }
        self.assertEqual(evaluate(data)["primary_endpoint_assessment"]["status"], "OPPOSITE_DIRECTION")

    def test_primary_endpoint_fingerprint_is_stable_and_covers_scientific_spec(self):
        endpoint = {
            "outcome_class": "FALSE_ACCEPT", "expected_direction": "LOWER",
            "analysis_population": "ALL_PAIRED_CASES", "alpha": 0.05,
            "registration_reference": "protocol-v1", "frozen_before_outcomes_review": True,
        }
        original = _primary_endpoint_spec_sha256(endpoint)
        reordered = dict(reversed(list(endpoint.items())))
        self.assertEqual(original, _primary_endpoint_spec_sha256(reordered))
        changed = dict(endpoint, alpha=0.01)
        self.assertNotEqual(original, _primary_endpoint_spec_sha256(changed))
        self.assertEqual(len(original), 64)

    def test_primary_endpoint_is_not_configured_by_default(self):
        assessment = evaluate(self.data)["primary_endpoint_assessment"]
        self.assertEqual(assessment["status"], "NOT_CONFIGURED")
        self.assertIsNone(assessment["endpoint"])

    def test_primary_endpoint_rejects_unverifiable_or_invalid_declarations(self):
        base = {
            "outcome_class": "FALSE_ACCEPT", "expected_direction": "LOWER",
            "analysis_population": "ALL_PAIRED_CASES", "alpha": 0.05,
            "registration_reference": "protocol-v1", "frozen_before_outcomes_review": True,
        }
        for field, value, message in [
            ("frozen_before_outcomes_review", False, "must be true"),
            ("alpha", True, "strictly between 0 and 1"),
            ("analysis_population", "UNIQUE_GOLD_CASES", "must be ALL_PAIRED_CASES"),
            ("registration_reference", "  ", "non-empty string"),
        ]:
            data = dict(self.data)
            data["primary_endpoint"] = dict(base, **{field: value})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                evaluate(data)

    def test_exact_mcnemar_is_symmetric_bounded_and_exact_for_small_pairs(self):
        self.assertEqual(_exact_mcnemar_p_value(0, 0), 1.0)
        self.assertEqual(_exact_mcnemar_p_value(6, 0), 0.03125)
        self.assertEqual(_exact_mcnemar_p_value(0, 6), 0.03125)
        for baseline_only in range(8):
            for dss_only in range(8):
                value = _exact_mcnemar_p_value(baseline_only, dss_only)
                self.assertGreaterEqual(value, 0.0)
                self.assertLessEqual(value, 1.0)
                self.assertEqual(
                    value,
                    _exact_mcnemar_p_value(dss_only, baseline_only),
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


class RegistrationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = {
            "outcome_class": "FALSE_ACCEPT",
            "expected_direction": "LOWER",
            "analysis_population": "ALL_PAIRED_CASES",
            "alpha": 0.05,
            "registration_reference": "protocol-v1",
            "frozen_before_outcomes_review": True,
        }
        self.record = {
            "record_version": "registration-evidence/v1",
            "registration_reference": "protocol-v1",
            "endpoint_spec_sha256": _primary_endpoint_spec_sha256(self.endpoint),
            "registered_at_utc": "2026-10-01T09:00:00Z",
            "outcomes_accessed_at_utc": "2026-10-02T09:00:00Z",
            "analysis_started_at_utc": "2026-10-02T10:00:00Z",
            "timestamp_evidence_reference": "archive://record-17",
        }

    def test_matching_digest_and_claimed_order_are_reported_without_trust_claim(self):
        result = verify_registration_evidence(self.endpoint, self.record)
        self.assertEqual(result["specification_integrity"], "MATCH")
        self.assertEqual(result["claimed_chronology"], "REGISTERED_BEFORE_OUTCOME_ACCESS")
        self.assertEqual(result["claimed_analysis_order"], "ANALYSIS_STRICTLY_AFTER_OUTCOME_ACCESS")
        self.assertEqual(result["timestamp_verification"], "NOT_INDEPENDENTLY_VERIFIED")

    def test_changed_endpoint_specification_fails_integrity(self):
        changed = dict(self.endpoint, alpha=0.01)
        result = verify_registration_evidence(changed, self.record)
        self.assertEqual(result["specification_integrity"], "MISMATCH")
        self.assertFalse(result["digest_matches"])

    def test_changed_registration_reference_fails_integrity(self):
        record = dict(self.record, registration_reference="other-record")
        result = verify_registration_evidence(self.endpoint, record)
        self.assertEqual(result["specification_integrity"], "MISMATCH")
        self.assertFalse(result["registration_reference_matches"])

    def test_registration_at_or_after_outcome_access_is_not_preregistered(self):
        record = dict(self.record, registered_at_utc="2026-10-02T09:00:00Z")
        result = verify_registration_evidence(self.endpoint, record)
        self.assertEqual(result["claimed_chronology"], "NOT_REGISTERED_BEFORE_OUTCOME_ACCESS")

    def test_analysis_before_outcome_access_is_flagged(self):
        record = dict(self.record, analysis_started_at_utc="2026-10-02T08:59:59Z")
        result = verify_registration_evidence(self.endpoint, record)
        self.assertEqual(result["claimed_analysis_order"], "ANALYSIS_NOT_STRICTLY_AFTER_OUTCOME_ACCESS")

    def test_non_utc_or_malformed_timestamp_is_rejected(self):
        for value in ("2026-10-01T09:00:00+00:00", "2026-02-30T09:00:00Z", "yesterday"):
            with self.subTest(value=value):
                record = dict(self.record, registered_at_utc=value)
                with self.assertRaisesRegex(ValueError, "ISO 8601 UTC|valid UTC"):
                    verify_registration_evidence(self.endpoint, record)

    def test_unknown_or_missing_record_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            verify_registration_evidence(self.endpoint, dict(self.record, outcome="WIN"))
        record = dict(self.record)
        del record["timestamp_evidence_reference"]
        with self.assertRaisesRegex(ValueError, "missing field"):
            verify_registration_evidence(self.endpoint, record)



    def test_registration_evidence_schema_has_usable_utc_timestamp_pattern(self):
        repo_root = Path(__file__).resolve().parents[1]
        schema_path = repo_root / "experiments" / "schemas" / "registration-evidence-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["record_version"]["const"], "registration-evidence/v1")
        pattern = schema["properties"]["registered_at_utc"]["pattern"]
        self.assertIsNotNone(re.fullmatch(pattern, "2026-10-01T09:00:00Z"))
        self.assertIsNotNone(re.fullmatch(pattern, "2026-10-01T09:00:00.123Z"))
        self.assertIsNone(re.fullmatch(pattern, "2026-10-01T09:00:00+00:00"))


    def test_analysis_with_same_recorded_timestamp_as_access_is_not_ordered(self):
        record = dict(self.record, analysis_started_at_utc="2026-10-02T09:00:00Z")
        result = verify_registration_evidence(self.endpoint, record)
        self.assertEqual(result["claimed_analysis_order"], "ANALYSIS_NOT_STRICTLY_AFTER_OUTCOME_ACCESS")


    def test_registration_evidence_cli_reports_unverified_timestamp_on_consistent_record(self):
        with tempfile.TemporaryDirectory() as directory:
            pilot_path = Path(directory) / "pilot.json"
            record_path = Path(directory) / "registration.json"
            pilot_path.write_text(json.dumps({"primary_endpoint": self.endpoint}), encoding="utf-8")
            record_path.write_text(json.dumps(self.record), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "experiments.registration_evidence",
                 str(pilot_path), str(record_path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["specification_integrity"], "MATCH")
            self.assertEqual(report["timestamp_verification"], "NOT_INDEPENDENTLY_VERIFIED")

    def test_registration_evidence_cli_returns_nonzero_for_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            pilot_path = Path(directory) / "pilot.json"
            record_path = Path(directory) / "registration.json"
            pilot_path.write_text(json.dumps({"primary_endpoint": self.endpoint}), encoding="utf-8")
            record_path.write_text(json.dumps(dict(self.record, endpoint_spec_sha256="0" * 64)), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "experiments.registration_evidence",
                 str(pilot_path), str(record_path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(json.loads(completed.stdout)["specification_integrity"], "MISMATCH")


class AuditEventChainTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.events = append_audit_event(
            self.events, event_id="evt-registration", event_type="REGISTRATION_FROZEN",
            occurred_at_utc="2026-10-01T09:00:00Z", actor_reference="reviewer-1",
            evidence_reference="archive://registration",
        )
        self.events = append_audit_event(
            self.events, event_id="evt-access-1", event_type="OUTCOME_ACCESS",
            occurred_at_utc="2026-10-02T09:00:00Z", actor_reference="analyst-1",
            evidence_reference="access-log://entry-1",
        )
        self.events = append_audit_event(
            self.events, event_id="evt-analysis", event_type="ANALYSIS_STARTED",
            occurred_at_utc="2026-10-02T09:01:00Z", actor_reference="analyst-1",
            evidence_reference="analysis-run://run-1",
        )

    def test_complete_chain_is_hash_linked_and_explicitly_unanchored(self):
        report = verify_event_chain(self.events)
        self.assertEqual(report["chain_integrity"], "VALID_PREFIX")
        self.assertEqual(report["required_event_sequence"], "COMPLETE")
        self.assertEqual(report["event_count"], 3)
        self.assertEqual(report["external_anchor_verification"], "NOT_VERIFIED")
        self.assertEqual(len(report["chain_head_sha256"]), 64)

    def test_content_tampering_is_detected(self):
        tampered = [dict(event) for event in self.events]
        tampered[1]["actor_reference"] = "different-actor"
        with self.assertRaisesRegex(ValueError, "event_sha256 does not match"):
            verify_event_chain(tampered)

    def test_reordering_is_detected(self):
        reordered = [self.events[1], self.events[0], self.events[2]]
        with self.assertRaisesRegex(ValueError, "non-contiguous sequence|previous_event_sha256"):
            verify_event_chain(reordered)

    def test_valid_prefix_is_not_misreported_as_complete(self):
        report = verify_event_chain(self.events[:2])
        self.assertEqual(report["chain_integrity"], "VALID_PREFIX")
        self.assertEqual(report["required_event_sequence"], "INCOMPLETE")
        self.assertFalse(report["analysis_started"])

    def test_every_outcome_access_can_be_recorded_including_after_analysis(self):
        extended = append_audit_event(
            self.events, event_id="evt-access-2", event_type="OUTCOME_ACCESS",
            occurred_at_utc="2026-10-02T09:02:00Z", actor_reference="analyst-1",
            evidence_reference="access-log://entry-2",
        )
        report = verify_event_chain(extended)
        self.assertEqual(report["event_count"], 4)
        self.assertEqual(report["required_event_sequence"], "COMPLETE")

    def test_analysis_cannot_precede_first_outcome_access(self):
        invalid = []
        invalid = append_audit_event(
            invalid, event_id="evt-registration", event_type="REGISTRATION_FROZEN",
            occurred_at_utc="2026-10-01T09:00:00Z", actor_reference="reviewer-1",
            evidence_reference="archive://registration",
        )
        with self.assertRaisesRegex(ValueError, "ANALYSIS_STARTED requires"):
            append_audit_event(
                invalid, event_id="evt-analysis", event_type="ANALYSIS_STARTED",
                occurred_at_utc="2026-10-01T10:00:00Z", actor_reference="analyst-1",
                evidence_reference="analysis-run://run-1",
            )

    def test_registration_must_be_first_and_analysis_can_start_only_once(self):
        with self.assertRaisesRegex(ValueError, "REGISTRATION_FROZEN"):
            append_audit_event(
                [], event_id="evt-access", event_type="OUTCOME_ACCESS",
                occurred_at_utc="2026-10-01T09:00:00Z", actor_reference="analyst-1",
                evidence_reference="access-log://entry-1",
            )
        with self.assertRaisesRegex(ValueError, "ANALYSIS_STARTED may occur only once"):
            append_audit_event(
                self.events, event_id="evt-analysis-2", event_type="ANALYSIS_STARTED",
                occurred_at_utc="2026-10-02T09:02:00Z", actor_reference="analyst-1",
                evidence_reference="analysis-run://run-2",
            )

    def test_equal_or_earlier_event_timestamp_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "strictly later"):
            append_audit_event(
                self.events, event_id="evt-late-access", event_type="OUTCOME_ACCESS",
                occurred_at_utc="2026-10-02T09:01:00Z", actor_reference="analyst-1",
                evidence_reference="access-log://entry-2",
            )

    def test_append_refuses_a_tampered_existing_prefix(self):
        tampered = [dict(event) for event in self.events]
        tampered[0]["evidence_reference"] = "changed"
        with self.assertRaisesRegex(ValueError, "event_sha256 does not match"):
            append_audit_event(
                tampered, event_id="evt-extra", event_type="OUTCOME_ACCESS",
                occurred_at_utc="2026-10-02T09:02:00Z", actor_reference="analyst-1",
                evidence_reference="access-log://entry-2",
            )

    def test_event_chain_schema_is_strict_and_uses_utc_pattern(self):
        repo_root = Path(__file__).resolve().parents[1]
        schema_path = repo_root / "experiments" / "schemas" / "audit-event-chain-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["type"], "array")
        self.assertFalse(schema["items"]["additionalProperties"])
        pattern = schema["items"]["properties"]["occurred_at_utc"]["pattern"]
        self.assertIsNotNone(re.fullmatch(pattern, "2026-10-01T09:00:00Z"))
        self.assertIsNone(re.fullmatch(pattern, "2026-10-01T09:00:00+00:00"))


    def test_non_string_event_type_and_non_integer_sequence_are_rejected(self):
        malformed_type = [dict(event) for event in self.events]
        malformed_type[1]["event_type"] = []
        with self.assertRaisesRegex(ValueError, "unsupported event_type"):
            verify_event_chain(malformed_type)
        malformed_sequence = [dict(event) for event in self.events]
        malformed_sequence[1]["sequence"] = 1.0
        with self.assertRaisesRegex(ValueError, "non-contiguous sequence"):
            verify_event_chain(malformed_sequence)

    def test_event_chain_cli_verifies_complete_chain_without_mutating_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            original = json.dumps(self.events, indent=2)
            path.write_text(original, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "experiments.audit_event_chain", str(path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["required_event_sequence"], "COMPLETE")
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_event_chain_cli_returns_nonzero_for_incomplete_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text(json.dumps(self.events[:2]), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "experiments.audit_event_chain", str(path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(json.loads(completed.stdout)["required_event_sequence"], "INCOMPLETE")

    def test_event_chain_timestamp_precision_is_bounded_to_microseconds(self):
        repo_root = Path(__file__).resolve().parents[1]
        schema_path = repo_root / "experiments" / "schemas" / "audit-event-chain-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        pattern = schema["items"]["properties"]["occurred_at_utc"]["pattern"]
        self.assertIsNotNone(re.fullmatch(pattern, "2026-10-01T09:00:00.123456Z"))
        self.assertIsNone(re.fullmatch(pattern, "2026-10-01T09:00:00.1234567Z"))


    def _checkpoint(self):
        return {
            "record_version": "audit-chain-checkpoint/v1",
            "registration_event_id": self.events[0]["event_id"],
            "checkpoint_sequence": 1,
            "checkpoint_event_sha256": self.events[1]["event_sha256"],
            "anchored_at_utc": "2026-10-02T09:00:01Z",
            "anchor_reference": "external-ledger://checkpoint-1",
        }

    def test_matching_checkpoint_binds_retained_prefix_but_does_not_claim_authentication(self):
        result = verify_external_checkpoint(self.events, self._checkpoint())
        self.assertEqual(result["checkpoint_binding"], "MATCH")
        self.assertEqual(result["checkpoint_time_order"], "NOT_BEFORE_EVENT")
        self.assertEqual(result["anchor_authentication"], "NOT_VERIFIED")

    def test_checkpoint_detects_digest_or_registration_identity_mismatch(self):
        checkpoint = dict(self._checkpoint(), checkpoint_event_sha256="0" * 64)
        result = verify_external_checkpoint(self.events, checkpoint)
        self.assertEqual(result["checkpoint_binding"], "MISMATCH")
        checkpoint = dict(self._checkpoint(), registration_event_id="other-registration")
        result = verify_external_checkpoint(self.events, checkpoint)
        self.assertEqual(result["checkpoint_binding"], "MISMATCH")

    def test_checkpoint_beyond_retained_chain_exposes_missing_prefix(self):
        checkpoint = dict(self._checkpoint(), checkpoint_sequence=9)
        result = verify_external_checkpoint(self.events, checkpoint)
        self.assertEqual(result["checkpoint_binding"], "MISMATCH")
        self.assertEqual(result["checkpoint_time_order"], "NOT_COMPARABLE")

    def test_checkpoint_timestamp_cannot_precede_anchored_event(self):
        checkpoint = dict(self._checkpoint(), anchored_at_utc="2026-10-02T08:59:59Z")
        result = verify_external_checkpoint(self.events, checkpoint)
        self.assertEqual(result["checkpoint_time_order"], "PRECEDES_EVENT")

    def test_checkpoint_rejects_unknown_fields_and_invalid_sequence(self):
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            verify_external_checkpoint(self.events, dict(self._checkpoint(), claimed=True))
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            verify_external_checkpoint(self.events, dict(self._checkpoint(), checkpoint_sequence=True))

    def test_checkpoint_schema_is_strict_and_uses_utc_timestamp(self):
        repo_root = Path(__file__).resolve().parents[1]
        schema_path = repo_root / "experiments" / "schemas" / "audit-chain-checkpoint-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        pattern = schema["properties"]["anchored_at_utc"]["pattern"]
        self.assertIsNotNone(re.fullmatch(pattern, "2026-10-02T09:00:01.123Z"))
        self.assertIsNone(re.fullmatch(pattern, "2026-10-02T09:00:01+00:00"))

    def test_cli_fails_when_supplied_checkpoint_does_not_match(self):
        with tempfile.TemporaryDirectory() as directory:
            events_path = Path(directory) / "events.json"
            checkpoint_path = Path(directory) / "checkpoint.json"
            events_path.write_text(json.dumps(self.events), encoding="utf-8")
            checkpoint_path.write_text(
                json.dumps(dict(self._checkpoint(), checkpoint_event_sha256="0" * 64)),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, "-m", "experiments.audit_event_chain",
                 str(events_path), "--checkpoint", str(checkpoint_path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 1)
            report = json.loads(completed.stdout)
            self.assertEqual(report["external_checkpoint"]["checkpoint_binding"], "MISMATCH")


if __name__ == "__main__":
    unittest.main()
