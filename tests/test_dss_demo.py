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

    def test_trace_identity_and_ruleset_metadata_are_deterministic(self):
        case = self.by_id["01-exact"]
        first, second = evaluate_case(case), evaluate_case(case)
        self.assertEqual(first["trace_id"], second["trace_id"])
        self.assertTrue(first["trace_id"].startswith("addr-"))
        self.assertEqual(first["ruleset_version"], "synthetic-address-demo/1.0")
        self.assertEqual(
            first["normalisation_rule"],
            "text-only Unicode casefold plus whitespace collapse",
        )

    def test_trace_identity_changes_when_terminal_decision_changes(self):
        case = json.loads(json.dumps(self.by_id["01-exact"]))
        verified = evaluate_case(case)
        case["candidates"][0]["postcode"] = "ZZ9 9ZZ"
        unresolved = evaluate_case(case)
        self.assertNotEqual(verified["trace_id"], unresolved["trace_id"])

    def test_malformed_case_still_receives_trace_metadata(self):
        result = evaluate_case(None)
        self.assertTrue(result["trace_id"].startswith("addr-"))
        self.assertEqual(result["ruleset_version"], "synthetic-address-demo/1.0")

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

    def test_candidate_trace_exposes_exact_field_evidence_and_selection(self):
        result = evaluate_case(self.by_id["01-exact"])
        candidate = result["candidate_trace"][0]
        self.assertEqual(candidate["candidate_id"], "A")
        self.assertTrue(candidate["retrieval"]["eligible"])
        self.assertEqual(candidate["disposition"], "SELECTED_EXACT")
        self.assertEqual(candidate["reason_codes"], ["ALL_IDENTITY_FIELDS_MATCH"])
        for field in ("premise", "street", "locality", "postcode"):
            self.assertTrue(candidate["field_comparisons"][field]["normalised_equal"])

    def test_candidate_trace_records_safe_one_edit_correction(self):
        result = evaluate_case(self.by_id["03-typo-correction"])
        candidate = result["candidate_trace"][0]
        self.assertEqual(result["terminal_state"], "CORRECTED")
        self.assertTrue(candidate["retrieval"]["eligible"])
        self.assertTrue(candidate["street_edit_distance_at_most_one"])
        self.assertFalse(candidate["field_comparisons"]["street"]["normalised_equal"])
        self.assertEqual(candidate["disposition"], "SELECTED_CORRECTED")
        self.assertTrue(all(candidate["protected_field_checks"].values()))

    def test_candidate_trace_explains_postcode_return_refusal(self):
        result = evaluate_case(self.by_id["04-postcode-conflict"])
        candidate = result["candidate_trace"][0]
        self.assertTrue(candidate["retrieval"]["eligible"])
        self.assertFalse(candidate["protected_field_checks"]["postcode"])
        self.assertEqual(candidate["disposition"], "REFUSED_RETURN_CHECK")
        self.assertIn("POSTCODE_RETURN_MISMATCH", candidate["reason_codes"])

    def test_candidate_trace_excludes_premise_and_locality_conflicts(self):
        valid = self.by_id["03-typo-correction"]
        for field, value, expected_reason in (
            ("premise", "99", "PREMISE_MISMATCH"),
            ("locality", "Elsewhere", "LOCALITY_MISMATCH"),
        ):
            case = json.loads(json.dumps(valid))
            case["candidates"][0][field] = value
            result = evaluate_case(case)
            candidate = result["candidate_trace"][0]
            self.assertFalse(candidate["retrieval"]["eligible"])
            self.assertEqual(candidate["disposition"], "REFUSED_RETRIEVAL")
            self.assertIn(expected_reason, candidate["reason_codes"])
            self.assertEqual(result["terminal_state"], "UNRESOLVED")

    def test_candidate_trace_marks_every_near_candidate_ambiguous(self):
        result = evaluate_case(self.by_id["05-ambiguous"])
        self.assertEqual(
            [item["disposition"] for item in result["candidate_trace"]],
            ["AMBIGUOUS", "AMBIGUOUS"],
        )
        self.assertTrue(all(
            "MULTIPLE_RETRIEVAL_ELIGIBLE_CANDIDATES" in item["reason_codes"]
            for item in result["candidate_trace"]
        ))
        self.assertIsNone(result["selected_candidate"])

    def test_candidate_trace_order_only_changes_presentation_order(self):
        case = json.loads(json.dumps(self.by_id["05-ambiguous"]))
        original = evaluate_case(case)
        case["candidates"].reverse()
        reversed_result = evaluate_case(case)
        self.assertEqual(original["terminal_state"], reversed_result["terminal_state"])
        self.assertEqual(original["reason_code"], reversed_result["reason_code"])
        self.assertEqual(
            [item["candidate_id"] for item in original["candidate_trace"]],
            ["E1", "E2"],
        )
        self.assertEqual(
            [item["candidate_id"] for item in reversed_result["candidate_trace"]],
            ["E2", "E1"],
        )

    def test_candidate_trace_is_deterministic(self):
        case = self.by_id["03-typo-correction"]
        self.assertEqual(evaluate_case(case)["candidate_trace"], evaluate_case(case)["candidate_trace"])

    def test_malformed_candidate_has_explicit_refusal_trace(self):
        case = json.loads(json.dumps(self.by_id["01-exact"]))
        case["candidates"].append(None)
        result = evaluate_case(case)
        malformed = result["candidate_trace"][1]
        self.assertEqual(malformed["disposition"], "REFUSED")
        self.assertEqual(malformed["reason_codes"], ["MALFORMED_CANDIDATE_RECORD"])
        self.assertEqual(result["terminal_state"], "UNRESOLVED")

    def test_return_check_detects_wrong_postcode(self):
        case = self.by_id["07-return-check-fails"]
        result = evaluate_case(case)
        self.assertEqual(result["terminal_state"], "UNRESOLVED")
        self.assertFalse(result["return_check"]["passed"])
        self.assertFalse(result["return_check"]["checks"]["postcode"])


if __name__ == "__main__":
    unittest.main()
