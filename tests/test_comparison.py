"""Tests for the optional fuzzy comparison baseline."""

import unittest

from run_test import fuzzy_resolve


class FuzzyBaselineTests(unittest.TestCase):
    def test_uses_same_case_and_postcode_normalisation(self):
        self.assertEqual(fuzzy_resolve("35 patrick place st87rf"), ("A001", 100.0))

    def test_abstains_when_best_score_is_tied(self):
        duplicate_authority = [
            {"id": "A001", "num": "35", "street": "PATRICK PLACE", "postcode": "ST8 7RF"},
            {"id": "A999", "num": "35", "street": "PATRICK PLACE", "postcode": "ST8 7RF"},
        ]
        self.assertEqual(
            fuzzy_resolve("35 PATRICK PLACE ST8 7RF", authority=duplicate_authority),
            (None, 100.0),
        )

    def test_abstains_below_declared_threshold(self):
        record = [
            {"id": "A001", "num": "35", "street": "PATRICK PLACE", "postcode": "ST8 7RF"},
        ]
        candidate, score = fuzzy_resolve(
            "completely unrelated input", threshold=80, authority=record
        )
        self.assertIsNone(candidate)
        self.assertLess(score, 80)


if __name__ == "__main__":
    unittest.main()
