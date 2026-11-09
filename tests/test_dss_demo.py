import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))

from dss_demo import edit_distance_at_most_one, evaluate_case  # noqa: E402


class DemoDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = json.loads((ROOT / "demo" / "cases.json").read_text(encoding="utf-8"))
        cls.by_id = {case["case_id"]: case for case in cls.cases}

    def test_edit_distance_refuses_non_text_values(self):
        for left, right in ((0, False), (None, ""), ([], []), ({}, {})):
            with self.subTest(left=left, right=right):
                self.assertFalse(edit_distance_at_most_one(left, right))
        self.assertTrue(edit_distance_at_most_one("High St", "High St"))
        self.assertTrue(edit_distance_at_most_one("High St", "High Stt"))

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

    def test_malformed_case_and_candidate_containers_are_refused(self):
        for malformed in (None, "case", [], 7):
            with self.subTest(case=malformed):
                result = evaluate_case(malformed)
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertEqual(result["reason_code"], "MALFORMED_CASE")
                self.assertEqual(result["evidence_class"], "INSUFFICIENT")

        valid = self.by_id["01-exact"]
        for intended in (None, [], "address"):
            case = dict(valid, intended=intended)
            result = evaluate_case(case)
            self.assertEqual(result["reason_code"], "MALFORMED_INTENDED_RECORD")

        for candidates in (None, {}, "candidate-list", (valid["candidates"][0],)):
            case = dict(valid, candidates=candidates)
            result = evaluate_case(case)
            self.assertEqual(result["terminal_state"], "UNRESOLVED")
            self.assertEqual(result["reason_code"], "MALFORMED_CANDIDATE_COLLECTION")

        for malformed_candidate in (None, "candidate", 12, []):
            case = dict(valid, candidates=[valid["candidates"][0], malformed_candidate])
            result = evaluate_case(case)
            self.assertEqual(result["terminal_state"], "UNRESOLVED")
            self.assertEqual(result["reason_code"], "MALFORMED_CANDIDATE_RECORD")

    def test_non_text_identity_fields_are_not_coerced_to_address_text(self):
        valid = self.by_id["01-exact"]
        for field, malformed in (
            ("premise", 0), ("street", False), ("locality", 17), ("postcode", []),
        ):
            case = json.loads(json.dumps(valid))
            case["intended"][field] = malformed
            result = evaluate_case(case)
            with self.subTest(side="intended", field=field):
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertEqual(result["reason_code"], "MISSING_REQUIRED_INTENDED_FIELD")

        for field, malformed in (
            ("premise", 0), ("street", False), ("locality", 17), ("postcode", []),
        ):
            case = json.loads(json.dumps(valid))
            case["candidates"][0][field] = malformed
            result = evaluate_case(case)
            with self.subTest(side="candidate", field=field):
                self.assertEqual(result["terminal_state"], "UNRESOLVED")
                self.assertEqual(result["reason_code"], "NO_SUPPORTED_CANDIDATE")

    def test_malformed_candidate_does_not_get_silently_ignored_beside_exact_match(self):
        valid = self.by_id["01-exact"]
        case = json.loads(json.dumps(valid))
        case["candidates"].append(None)
        result = evaluate_case(case)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertEqual(result["reason_code"], "MALFORMED_CANDIDATE_RECORD")
        self.assertIsNone(result["selected_candidate"])

    def test_malformed_candidate_identifiers_use_safe_trace_labels(self):
        valid = self.by_id["01-exact"]
        for candidate_id in (None, 0, {}, [], "   "):
            case = json.loads(json.dumps(valid))
            case["candidates"][0]["candidate_id"] = candidate_id
            result = evaluate_case(case)
            with self.subTest(candidate_id=candidate_id):
                self.assertEqual(result["terminal_state"], "VERIFIED")
                self.assertEqual(result["candidate_ids"], ["candidate-1"])
                self.assertEqual(result["selected_candidate"], "candidate-1")

    def test_return_check_detects_wrong_postcode(self):
        case = self.by_id["07-return-check-fails"]
        result = evaluate_case(case)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertFalse(result["return_check"]["passed"])
        self.assertFalse(result["return_check"]["checks"]["postcode"])


if __name__ == "__main__":
    unittest.main()
