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
        self.assertEqual(len(rows), 13)
        self.assertTrue(any(len(row["mutations"]) == 2 for row in rows))

    def test_oracle_metadata_is_not_passed_to_evaluator(self):
        row = build_dataset()[2]
        self.assertEqual(set(row["case"]), {"case_id", "intended", "candidates"})
        trace = evaluate_case(row["case"])
        self.assertEqual((trace["terminal_state"], trace["reason_code"]),
                         ("UNRESOLVED", "NO_SUPPORTED_CANDIDATE"))

    def test_protected_identity_mutations_never_auto_accept(self):
        for row in build_dataset():
            if row["mutations"] and row["scenario"] != "formatting-only" and row["scenario"] != "street-one-edit-only":
                with self.subTest(scenario=row["scenario"]):
                    self.assertNotEqual(evaluate_case(row["case"])["terminal_state"], "VERIFIED")

    def test_one_street_edit_corrects_but_multiple_edits_are_refused(self):
        rows = {r["scenario"]: r for r in build_dataset()}
        self.assertEqual(evaluate_case(rows["street-one-edit-only"]["case"])["terminal_state"], "CORRECTED")
        self.assertEqual(evaluate_case(rows["street-multiple-edits-only"]["case"])["terminal_state"], "UNRESOLVED")

    def test_postcode_conflict_survives_near_street_candidate(self):
        row = next(r for r in build_dataset() if r["scenario"] == "street-plus-postcode")
        trace = evaluate_case(row["case"])
        self.assertEqual(trace["reason_code"], "RETURN_CHECK_FAILED")
        self.assertFalse(trace["return_check"]["checks"]["postcode"])

    def test_benchmark_has_expected_counts_and_zero_false_accepts(self):
        report = benchmark()
        self.assertTrue(report["passed"])
        self.assertEqual(report["case_count"], 13)
        self.assertEqual(report["oracle_mismatches"], [])
        self.assertEqual(report["mutated_false_accepts"], 0)
        self.assertEqual(report["state_counts"], {"CORRECTED": 1, "UNRESOLVED": 10, "VERIFIED": 2})

if __name__ == "__main__":
    unittest.main()
