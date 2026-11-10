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
        self.assertEqual(report["report_version"], "paired-pilot-metrics/1.2")
        self.assertEqual(report["case_count"], 4)
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
        self.assertEqual(matrix["FALSE_REJECT"]["CORRECT_ABSTENTION"], 1)

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

    def test_whitespace_only_provenance_is_rejected(self):
        data = json.loads(json.dumps(self.data))
        data["dataset_id"] = "   "
        with self.assertRaisesRegex(ValueError, "dataset_id must be a non-empty string"):
            evaluate(data)

if __name__ == "__main__":
    unittest.main()
