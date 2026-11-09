import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "experiments")]
from address_mutation_bench import benchmark, build_dataset
from dss_demo import evaluate_case

class AddressMutationBenchmarkTests(unittest.TestCase):
    def test_deterministic_13_case_single_and_pair_matrix(self):
        rows = build_dataset()
        self.assertEqual(rows, build_dataset())
        self.assertEqual(len(rows), 18)
        self.assertTrue(any(len(row["mutations"]) == 2 for row in rows))

    def test_oracle_metadata_is_not_passed_to_evaluator(self):
        row = build_dataset()[2]
        self.assertEqual(set(row["case"]), {"case_id", "intended", "candidates"})
        trace = evaluate_case(row["case"])
        self.assertEqual((trace["terminal_state"], trace["reason_code"]),
                         ("UNRESOLVED", "NO_SUPPORTED_CANDIDATE"))

    def test_protected_identity_mutations_never_auto_accept(self):
        for row in build_dataset():
            if row["mutations"] and row["scenario"] not in {"formatting-only", "street-one-edit-only", "street-substitution", "street-insertion"}:
                with self.subTest(scenario=row["scenario"]):
                    self.assertNotEqual(evaluate_case(row["case"])["terminal_state"], "VERIFIED")

    def test_levenshtein_edit_operations_and_transposition_boundary(self):
        rows = {r["scenario"]: r for r in build_dataset()}
        for scenario in ("street-one-edit-only", "street-substitution", "street-insertion"):
            with self.subTest(scenario=scenario):
                self.assertEqual(evaluate_case(rows[scenario]["case"])["terminal_state"], "CORRECTED")
        for scenario in ("street-multiple-edits-only", "street-transposition"):
            with self.subTest(scenario=scenario):
                self.assertEqual(evaluate_case(rows[scenario]["case"])["terminal_state"], "UNRESOLVED")

    def test_postcode_conflict_survives_near_street_candidate(self):
        row = next(r for r in build_dataset() if r["scenario"] == "street-plus-postcode")
        trace = evaluate_case(row["case"])
        self.assertEqual(trace["reason_code"], "RETURN_CHECK_FAILED")
        self.assertFalse(trace["return_check"]["checks"]["postcode"])

    def test_candidate_cardinality_and_order_never_create_false_accepts(self):
        rows = {row["scenario"]: row for row in build_dataset()}
        for scenario, expected_reason in (
            ("duplicate-exact-candidates", "MULTIPLE_EXACT_CANDIDATES"),
            ("ambiguous-near-candidates", "AMBIGUOUS_CANDIDATES"),
        ):
            case = rows[scenario]["case"]
            forward = evaluate_case(case)
            reversed_case = dict(case, candidates=list(reversed(case["candidates"])))
            reverse = evaluate_case(reversed_case)
            self.assertEqual(forward["terminal_state"], "UNRESOLVED")
            self.assertEqual(forward["reason_code"], expected_reason)
            self.assertEqual(
                (forward["terminal_state"], forward["reason_code"]),
                (reverse["terminal_state"], reverse["reason_code"]),
            )

    def test_benchmark_has_expected_counts_and_zero_false_accepts(self):
        report = benchmark()
        self.assertTrue(report["passed"], report["oracle_mismatches"])
        self.assertEqual(report["case_count"], 18)
        self.assertEqual(report["oracle_mismatches"], [])
        self.assertEqual(report["mutated_false_accepts"], 0)
        self.assertEqual(report["state_counts"], {"CORRECTED": 3, "UNRESOLVED": 13, "VERIFIED": 2})

if __name__ == "__main__":
    unittest.main()
