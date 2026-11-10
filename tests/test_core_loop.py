"""Unit tests for the original ∂ss address-resolution loop.

These tests exercise the core loop independently of the later synthetic demo
and benchmark implementations.
"""
import unittest

from dss_loop import (
    DSSLoop,
    Resolution,
    field_match,
    resolve_address,
    operate_address,
    check_address,
)


class CoreLoopTests(unittest.TestCase):
    def setUp(self):
        self.loop = DSSLoop(resolve_address, operate_address, check_address)

    def test_exact_address_reaches_verified(self):
        trace = self.loop.land("A001", "35 PATRICK PLACE ST8 7RF")

        self.assertEqual(trace.intended, "A001")
        self.assertEqual(trace.observed, "A001")
        self.assertEqual(trace.check, "PASS")
        self.assertEqual(trace.terminal, "VERIFIED")

    def test_single_street_edit_reaches_corrected(self):
        trace = self.loop.land("A002", "33 REDRIFE ROAD E14 8BX")

        self.assertEqual(trace.observed, "A002")
        self.assertEqual(trace.check, "PASS")
        self.assertEqual(trace.terminal, "CORRECTED")
        self.assertIn("CORRECTED", " ".join(trace.resolution.evidence))

    def test_compressed_postcode_is_normalised_before_resolution(self):
        trace = self.loop.land("A001", "35 patrick place st87rf")

        self.assertEqual(trace.observed, "A001")
        self.assertEqual(trace.terminal, "VERIFIED")

    def test_conflicting_postcode_is_unresolved(self):
        trace = self.loop.land("A001", "35 PATRICK PLACE ST6 6LS")

        self.assertIsNone(trace.observed)
        self.assertEqual(trace.terminal, "UNRESOLVED")

    def test_unknown_address_is_unresolved(self):
        trace = self.loop.land("A005", "99 UNKNOWN STREET ZZ9 9ZZ")

        self.assertIsNone(trace.observed)
        self.assertEqual(trace.terminal, "UNRESOLVED")

    def test_one_edit_field_match_is_correction(self):
        self.assertEqual(field_match("REDRIFE ROAD", "REDRIFFE ROAD"), "CORRECTED")

    def test_multiple_edit_field_match_fails(self):
        self.assertEqual(field_match("Kng Strret", "King Street"), "FAIL")

    def test_failed_return_check_refuses_candidate(self):
        loop = DSSLoop(
            resolve_fn=lambda incoming: Resolution(candidate="candidate", evidence=["exact"]),
            operate_fn=lambda candidate: "wrong-observation",
            check_fn=lambda intended, observed, epsilon: "FAIL",
        )

        trace = loop.land("intended", "incoming")

        self.assertEqual(trace.observed, "wrong-observation")
        self.assertEqual(trace.check, "FAIL")
        self.assertEqual(trace.terminal, "UNRESOLVED")

    def test_inconclusive_return_check_remains_unresolved(self):
        loop = DSSLoop(
            resolve_fn=lambda incoming: Resolution(candidate="candidate", evidence=["exact"]),
            operate_fn=lambda candidate: "observation",
            check_fn=lambda intended, observed, epsilon: "INCONCLUSIVE",
        )

        trace = loop.land("intended", "incoming")

        self.assertEqual(trace.check, "INCONCLUSIVE")
        self.assertEqual(trace.terminal, "UNRESOLVED")

    def test_missing_candidate_skips_operation_and_return_check(self):
        calls = []
        loop = DSSLoop(
            resolve_fn=lambda incoming: Resolution(candidate=None, evidence=["no candidate"]),
            operate_fn=lambda candidate: calls.append("operate"),
            check_fn=lambda intended, observed, epsilon: calls.append("check"),
        )

        trace = loop.land("intended", "incoming")

        self.assertEqual(trace.terminal, "UNRESOLVED")
        self.assertEqual(calls, [])
        self.assertIsNone(trace.observed)
        self.assertIsNone(trace.check)


    def test_valid_candidate_for_different_identity_remains_unresolved(self):
        # A valid address match is not enough: it must match the intended ID.
        trace = self.loop.land("A001", "33 REDRIFFE ROAD E14 8BX")

        self.assertEqual(trace.observed, "A002")
        self.assertEqual(trace.check, "FAIL")
        self.assertEqual(trace.terminal, "UNRESOLVED")

    def test_single_postcode_edit_is_recorded_as_correction(self):
        trace = self.loop.land("A001", "35 PATRICK PLACE ST8 7RG")

        self.assertEqual(trace.observed, "A001")
        self.assertEqual(trace.check, "PASS")
        self.assertEqual(trace.terminal, "CORRECTED")
        self.assertIn("postcode=CORRECTED", " ".join(trace.resolution.evidence))


if __name__ == "__main__":
    unittest.main()
