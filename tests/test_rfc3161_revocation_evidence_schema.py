"""Structural validation tests for the draft RFC 3161 revocation envelope.

These tests validate the JSON contract only. They do not authenticate DER
objects, verify signatures, or establish certificate revocation status.
"""
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "experiments"
    / "schemas"
    / "rfc3161-tsa-revocation-evidence-v1-draft.schema.json"
)


class RFC3161RevocationEvidenceSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(
            cls.schema, format_checker=FormatChecker()
        )

    def _base_record(self, evidence_type):
        return {
            "record_version": "rfc3161-tsa-revocation-evidence/v1-draft",
            "evidence_id": "synthetic-evidence-001",
            "evidence_type": evidence_type,
            "der_base64": "AA==",
            "der_sha256": "a" * 64,
            "acquired_at_utc": "2026-11-10T14:00:00Z",
            "acquisition_clock_trust": "CALLER_ASSERTED",
            "acquisition_reference": "synthetic-fixture://revocation-evidence",
            "target_certificate": {
                "certificate_der_sha256": "b" * 64,
                "subject_spki_sha256": "e" * 64,
                "issuer_name_der_sha256": "c" * 64,
                "issuer_certificate_der_sha256": "f" * 64,
                "issuer_spki_sha256": "d" * 64,
                "serial_hex": "2a",
            },
            "claimed_binding": {
                "serial_hex": "2a",
            },
        }

    def test_valid_complete_crl_envelope(self):
        record = self._base_record("CRL")
        record["claimed_binding"]["issuer_name_der_sha256"] = "c" * 64
        record["parser_observations"] = {
            "this_update_utc": "2026-11-10T13:00:00Z",
            "next_update_utc": "2026-11-11T13:00:00Z",
            "crl_number": "42",
            "crl_scope_complete": True,
            "indirect_crl": False,
            "delta_crl": False,
        }
        self.assertEqual(list(self.validator.iter_errors(record)), [])

    def test_valid_ocsp_envelope_requires_full_cert_id(self):
        record = self._base_record("OCSP_BASIC_RESPONSE")
        record["claimed_binding"].update({
            "cert_id_hash_algorithm": "sha256",
            "cert_id_issuer_name_hash": "e" * 64,
            "cert_id_issuer_key_hash": "f" * 64,
        })
        record["parser_observations"] = {
            "this_update_utc": "2026-11-10T13:00:00Z",
            "next_update_utc": "2026-11-10T14:30:00Z",
            "produced_at_utc": "2026-11-10T13:01:00Z",
            "ocsp_status": "good",
        }
        self.assertEqual(list(self.validator.iter_errors(record)), [])

    def test_ocsp_without_issuer_key_hash_is_rejected(self):
        record = self._base_record("OCSP_BASIC_RESPONSE")
        record["claimed_binding"].update({
            "cert_id_hash_algorithm": "sha256",
            "cert_id_issuer_name_hash": "e" * 64,
        })
        self.assertTrue(list(self.validator.iter_errors(record)))

    def test_crl_without_issuer_binding_is_rejected(self):
        record = self._base_record("CRL")
        self.assertTrue(list(self.validator.iter_errors(record)))

    def test_unknown_fields_are_rejected(self):
        record = self._base_record("CRL")
        record["claimed_binding"]["issuer_name_der_sha256"] = "c" * 64
        record["unreviewed_status"] = "GOOD"
        self.assertTrue(list(self.validator.iter_errors(record)))

    def test_bad_digest_and_non_utc_acquisition_time_are_rejected(self):
        record = self._base_record("CRL")
        record["claimed_binding"]["issuer_name_der_sha256"] = "c" * 64
        record["der_sha256"] = "A" * 64
        record["acquired_at_utc"] = "2026-11-10T14:00:00+01:00"
        self.assertTrue(list(self.validator.iter_errors(record)))


if __name__ == "__main__":
    unittest.main()
