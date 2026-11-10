"""Unit tests for the RFC 3161 timestamp verification boundary."""
import hashlib
import subprocess
import unittest
from unittest.mock import patch

from experiments.rfc3161_timestamp import (
    trust_anchor_sha256,
    verify_rfc3161_timestamp,
)


class RFC3161TimestampTests(unittest.TestCase):
    def setUp(self):
        self.token = b"synthetic-der-token"
        self.data = b"exact checkpoint payload"
        self.anchor = b"-----BEGIN CERTIFICATE-----\nsynthetic-anchor\n-----END CERTIFICATE-----\n"
        self.pin = {
            "sha256": trust_anchor_sha256(self.anchor),
            "source_reference": "operator-provisioned://synthetic-test-anchor",
        }
        self.time_text = (
            "Status info:  Granted.\n"
            "Time stamp: Nov 10 13:00:00 2026 GMT\n"
        )

    @patch("experiments.rfc3161_timestamp.subprocess.run")
    def test_valid_token_uses_claimed_time_and_explicit_anchor(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, self.time_text, ""),
            subprocess.CompletedProcess([], 0, "Verification: OK\n", ""),
        ]
        result = verify_rfc3161_timestamp(
            self.token, self.data, self.anchor, self.pin,
            intermediates_pem=b"-----BEGIN CERTIFICATE-----\nsynthetic-intermediate\n-----END CERTIFICATE-----\n",
        )
        self.assertEqual(result["timestamp_verification"], "VALID")
        self.assertEqual(result["message_imprint"], "MATCH")
        self.assertEqual(result["tsa_asserted_gen_time_utc"], "2026-11-10T13:00:00Z")
        self.assertEqual(result["certificate_validation_time"], "TOKEN_GEN_TIME")
        self.assertEqual(result["anchor_provenance"], "NOT_ESTABLISHED")
        self.assertEqual(result["tsa_certificate_revocation"], "NOT_CHECKED")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")
        self.assertEqual(result["event_truth"], "NOT_ESTABLISHED")
        verify_args = run.call_args_list[1].args[0]
        self.assertIn("-attime", verify_args)
        self.assertEqual(verify_args[verify_args.index("-attime") + 1], "1794315600")
        self.assertIn("timestampsign", verify_args)
        self.assertIn("-CApath", verify_args)
        self.assertTrue(verify_args[verify_args.index("-CApath") + 1].endswith("empty-ca-path"))
        self.assertIn("-untrusted", verify_args)

    @patch("experiments.rfc3161_timestamp.subprocess.run")
    def test_pin_mismatch_blocks_all_openssl_calls(self, run):
        bad_pin = dict(self.pin, sha256="0" * 64)
        result = verify_rfc3161_timestamp(self.token, self.data, self.anchor, bad_pin)
        self.assertEqual(result["timestamp_verification"], "TRUST_ANCHOR_PIN_MISMATCH")
        self.assertEqual(result["token_signature_and_path"], "NOT_PERFORMED")
        self.assertEqual(result["tsa_certificate_revocation"], "NOT_CHECKED")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")
        run.assert_not_called()

    @patch("experiments.rfc3161_timestamp.subprocess.run")
    def test_invalid_timestamp_signature_or_chain_fails_closed(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, self.time_text, ""),
            subprocess.CompletedProcess([], 1, "", "certificate verify error"),
        ]
        result = verify_rfc3161_timestamp(self.token, self.data, self.anchor, self.pin)
        self.assertEqual(result["timestamp_verification"], "INVALID")
        self.assertEqual(result["message_imprint"], "NOT_ESTABLISHED")
        self.assertEqual(result["timestamp_authentication"], "NOT_ESTABLISHED")
        self.assertEqual(result["tsa_certificate_revocation"], "NOT_CHECKED")
        self.assertEqual(result["historical_revocation_assurance"], "NOT_ESTABLISHED")

    @patch("experiments.rfc3161_timestamp.subprocess.run")
    def test_unparseable_token_is_not_verified(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, "", "bad token")
        result = verify_rfc3161_timestamp(self.token, self.data, self.anchor, self.pin)
        self.assertEqual(result["timestamp_verification"], "INVALID_TOKEN")
        self.assertEqual(result["token_signature_and_path"], "NOT_VERIFIED")
        run.assert_called_once()

    @patch("experiments.rfc3161_timestamp.subprocess.run")
    def test_fractional_generation_time_is_rejected_not_rounded(self, run):
        fractional = "Time stamp: Nov 10 13:00:00.125 2026 GMT\n"
        run.return_value = subprocess.CompletedProcess([], 0, fractional, "")
        result = verify_rfc3161_timestamp(self.token, self.data, self.anchor, self.pin)
        self.assertEqual(result["timestamp_verification"], "INVALID_TOKEN")
        self.assertEqual(result["token_signature_and_path"], "NOT_VERIFIED")

    @patch("experiments.rfc3161_timestamp.subprocess.run")
    def test_missing_openssl_is_unavailable_not_valid(self, run):
        run.side_effect = FileNotFoundError
        result = verify_rfc3161_timestamp(self.token, self.data, self.anchor, self.pin)
        self.assertEqual(result["timestamp_verification"], "VERIFICATION_UNAVAILABLE")
        self.assertEqual(result["token_signature_and_path"], "NOT_PERFORMED")

    @patch("experiments.rfc3161_timestamp.subprocess.run")
    def test_timeout_is_unavailable_not_valid(self, run):
        run.side_effect = subprocess.TimeoutExpired("openssl", 10)
        result = verify_rfc3161_timestamp(self.token, self.data, self.anchor, self.pin)
        self.assertEqual(result["timestamp_verification"], "VERIFICATION_UNAVAILABLE")
        self.assertEqual(result["token_signature_and_path"], "NOT_COMPLETED")

    def test_malformed_pin_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            verify_rfc3161_timestamp(
                self.token, self.data, self.anchor, dict(self.pin, trusted=True)
            )

    def test_non_pem_anchor_rejected(self):
        with self.assertRaisesRegex(ValueError, "PEM certificate"):
            verify_rfc3161_timestamp(
                self.token, self.data, b"not a certificate", self.pin
            )

    def test_empty_token_rejected(self):
        with self.assertRaisesRegex(ValueError, "token_der"):
            verify_rfc3161_timestamp(b"", self.data, self.anchor, self.pin)

    def test_non_bytes_payload_rejected(self):
        with self.assertRaisesRegex(ValueError, "data must be bytes"):
            verify_rfc3161_timestamp(self.token, "not bytes", self.anchor, self.pin)


if __name__ == "__main__":
    unittest.main()
