"""Tests for explicit audit trust-store validation and key eligibility."""
import base64
import unittest

from experiments.trust_store import resolve_eligible_key, validate_trust_store

PUBLIC_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
PURPOSE = "AUDIT_CHAIN_CHECKPOINT"


def sample_store():
    return {
        "record_version": "audit-trust-store/v1",
        "keys": [{
            "key_id": "example-key-01",
            "authority_name": "Example Authority (synthetic)",
            "algorithm": "Ed25519",
            "public_key_base64": PUBLIC_KEY,
            "purposes": [PURPOSE],
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "valid_until_utc": "2027-01-01T00:00:00Z",
            "status": "ACTIVE",
            "trust_basis_reference": "synthetic://policy/example",
        }],
    }


class TrustStoreTests(unittest.TestCase):
    def test_valid_store_is_only_structurally_valid(self):
        report = validate_trust_store(sample_store())
        self.assertEqual(report["trust_store_integrity"], "VALID")
        self.assertEqual(report["signature_verification"], "NOT_PERFORMED")
        self.assertEqual(report["authority_authentication"], "NOT_ESTABLISHED")

    def test_eligible_key_is_not_reported_as_authenticated(self):
        result = resolve_eligible_key(sample_store(), key_id="example-key-01",
            purpose=PURPOSE, at_utc="2026-11-10T12:00:00Z")
        self.assertEqual(result["key_eligibility"], "ELIGIBLE_FOR_SIGNATURE_CHECK")
        self.assertEqual(result["signature_verification"], "NOT_PERFORMED")
        self.assertEqual(result["authority_authentication"], "NOT_ESTABLISHED")

    def test_unknown_key_fails_closed(self):
        result = resolve_eligible_key(sample_store(), key_id="not-allowlisted",
            purpose=PURPOSE, at_utc="2026-11-10T12:00:00Z")
        self.assertEqual(result["key_eligibility"], "UNKNOWN_KEY")
        self.assertNotIn("public_key_base64", result)

    def test_wrong_purpose_fails_closed(self):
        result = resolve_eligible_key(sample_store(), key_id="example-key-01",
            purpose="OTHER", at_utc="2026-11-10T12:00:00Z")
        self.assertEqual(result["key_eligibility"], "PURPOSE_NOT_ALLOWED")
        self.assertIsNone(result["public_key_base64"])

    def test_revoked_key_fails_closed(self):
        store = sample_store()
        store["keys"][0]["status"] = "REVOKED"
        result = resolve_eligible_key(store, key_id="example-key-01",
            purpose=PURPOSE, at_utc="2026-11-10T12:00:00Z")
        self.assertEqual(result["key_eligibility"], "KEY_NOT_ACTIVE")

    def test_validity_interval_is_half_open(self):
        result = resolve_eligible_key(sample_store(), key_id="example-key-01",
            purpose=PURPOSE, at_utc="2027-01-01T00:00:00Z")
        self.assertEqual(result["key_eligibility"], "OUTSIDE_KEY_VALIDITY")

    def test_duplicate_key_ids_rejected(self):
        store = sample_store()
        store["keys"].append(dict(store["keys"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate key_id"):
            validate_trust_store(store)

    def test_malformed_public_key_rejected(self):
        store = sample_store()
        store["keys"][0]["public_key_base64"] = base64.b64encode(b"short").decode("ascii")
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            validate_trust_store(store)

    def test_unknown_fields_rejected(self):
        store = sample_store()
        store["keys"][0]["is_trusted"] = True
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            validate_trust_store(store)

    def test_empty_allowlist_confers_no_eligibility(self):
        store = {"record_version": "audit-trust-store/v1", "keys": []}
        self.assertEqual(validate_trust_store(store)["key_count"], 0)
        result = resolve_eligible_key(store, key_id="anything", purpose=PURPOSE,
            at_utc="2026-11-10T12:00:00Z")
        self.assertEqual(result["key_eligibility"], "UNKNOWN_KEY")

    def test_non_increasing_validity_rejected(self):
        store = sample_store()
        store["keys"][0]["valid_until_utc"] = store["keys"][0]["valid_from_utc"]
        with self.assertRaisesRegex(ValueError, "validity interval"):
            validate_trust_store(store)

    def test_non_string_status_rejected_cleanly(self):
        store = sample_store()
        store["keys"][0]["status"] = []
        with self.assertRaisesRegex(ValueError, "status must be"):
            validate_trust_store(store)

    def test_non_string_public_key_rejected_cleanly(self):
        store = sample_store()
        store["keys"][0]["public_key_base64"] = 123
        with self.assertRaisesRegex(ValueError, "must be a string"):
            validate_trust_store(store)


if __name__ == "__main__":
    unittest.main()
