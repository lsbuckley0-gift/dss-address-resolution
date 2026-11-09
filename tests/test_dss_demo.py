import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))

from dss_demo import evaluate_case  # noqa: E402


class DemoDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = json.loads((ROOT / "demo" / "cases.json").read_text(encoding="utf-8"))
        cls.by_id = {case["case_id"]: case for case in cls.cases}

    def test_exact_record_is_verified(self):
        result = evaluate_case(self.by_id["01-exact"])
        self.assertEqual(result["terminal_state"], "VERIFIED")

    def test_formatting_variation_is_verified(self):
        result = evaluate_case(self.by_id["02-formatting"])
        self.assertEqual(result["terminal_state"], "VERIFIED")

    def test_unique_one_edit_candidate_is_corrected(self):
        result = evaluate_case(self.by_id["03-typo-correction"])
        self.assertEqual(result["terminal_state"], "CORRECTED")
        self.assertTrue(result["return_check"]["passed"])

    def test_exact_match_has_shared_consistent_evidence_class(self):
        result = evaluate_case(self.by_id["01-exact"])
        self.assertEqual(result["evidence_class"], "SUFFICIENT_AND_CONSISTENT")
        self.assertEqual(result["reason_codes"], ["EXACT_IDENTITY_FIELDS"])

    def test_postcode_conflict_has_shared_conflicting_evidence_class(self):
        result = evaluate_case(self.by_id["04-postcode-conflict"])
        self.assertEqual(result["evidence_class"], "CONFLICTING")
        self.assertEqual(result["reason_codes"], ["RETURN_CHECK_FAILED"])

    def test_no_candidate_is_insufficient_not_conflicting(self):
        result = evaluate_case(self.by_id["06-no-candidate"])
        self.assertEqual(result["evidence_class"], "INSUFFICIENT")

    def test_multiple_candidates_are_ambiguous(self):
        result = evaluate_case(self.by_id["05-ambiguous"])
        self.assertEqual(result["evidence_class"], "AMBIGUOUS")

    def test_postcode_conflict_is_refused(self):
        result = evaluate_case(self.by_id["04-postcode-conflict"])
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertEqual(result["reason_code"], "RETURN_CHECK_FAILED")

    def test_multiple_candidates_are_unresolved(self):
        result = evaluate_case(self.by_id["05-ambiguous"])
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertEqual(result["reason_code"], "AMBIGUOUS_CANDIDATES")

    def test_missing_candidate_is_unresolved(self):
        result = evaluate_case(self.by_id["06-no-candidate"])
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertEqual(result["reason_code"], "NO_SUPPORTED_CANDIDATE")

    def test_return_check_detects_wrong_postcode(self):
        case = self.by_id["07-return-check-fails"]
        result = evaluate_case(case)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertFalse(result["return_check"]["passed"])
        self.assertFalse(result["return_check"]["checks"]["postcode"])


if __name__ == "__main__":
    unittest.main()
