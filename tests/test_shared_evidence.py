"""Tests for the shared evidence classification contract."""
import unittest

from dss_core.evidence import classify_evidence


class SharedEvidenceTests(unittest.TestCase):
    def test_complete_consistent_evidence(self):
        self.assertEqual(classify_evidence(), "SUFFICIENT_AND_CONSISTENT")

    def test_missing_evidence(self):
        self.assertEqual(classify_evidence(missing=True), "INSUFFICIENT")

    def test_conflicting_evidence(self):
        self.assertEqual(classify_evidence(conflicting=True), "CONFLICTING")

    def test_ambiguous_evidence(self):
        self.assertEqual(classify_evidence(ambiguous=True), "AMBIGUOUS")

    def test_missing_and_conflicting_evidence_is_mixed(self):
        self.assertEqual(
            classify_evidence(missing=True, conflicting=True),
            "MIXED",
        )
