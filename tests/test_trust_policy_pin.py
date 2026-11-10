"""Tests for out-of-band trust-policy digest pinning."""
import base64
import unittest

from experiments.trust_policy_pin import (
    canonical_trust_store_bytes,
    trust_store_sha256,
    verify_trust_store_pin,
)

PUBLIC_KEY = base64.b64encode(bytes(range(32))).decode("ascii")


def sample_store():
    return {
        "record_version": "audit-trust-store/v1",
        "keys": [{
            "key_id": "example-key-01",
            "authority_name": "Example Authority (synthetic)",
            "algorithm": "Ed25519",
            "public_key_base64": PUBLIC_KEY,
            "purposes": ["AUDIT_CHAIN_CHECKPOINT"],
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "valid_until_utc": "2027-01-01T00:00:00Z",
            "status": "ACTIVE",
            "trust_basis_reference": "synthetic://policy/example",
        }],
    }


class TrustPolicyPinTests(unittest.TestCase):
    def make_pin(self, store):
        return {
            "sha256": trust_store_sha256(store),
            "source_reference": "operator-provisioned://policy-pin/01",
        }

    def test_matching_out_of_band_pin(self):
        store = sample_store()
        result = verify_trust_store_pin(store, self.make_pin(store))
        self.assertEqual(result["trust_policy_pin"], "MATCH")
        self.assertEqual(result["pin_source_authentication"], "NOT_INDEPENDENTLY_AUTHENTICATED")
        self.assertEqual(result["trust_policy_authentication"], "NOT_ESTABLISHED")

    def test_key_status_change_breaks_pin(self):
        store = sample_store()
        pin = self.make_pin(store)
        store["keys"][0]["status"] = "REVOKED"
        self.assertEqual(verify_trust_store_pin(store, pin)["trust_policy_pin"], "MISMATCH")

    def test_purpose_change_breaks_pin(self):
        store = sample_store()
        pin = self.make_pin(store)
        store["keys"][0]["purposes"] = ["OTHER"]
        self.assertEqual(verify_trust_store_pin(store, pin)["trust_policy_pin"], "MISMATCH")

    def test_validity_change_breaks_pin(self):
        store = sample_store()
        pin = self.make_pin(store)
        store["keys"][0]["valid_until_utc"] = "2026-12-31T00:00:00Z"
        self.assertEqual(verify_trust_store_pin(store, pin)["trust_policy_pin"], "MISMATCH")

    def test_trust_basis_change_breaks_pin(self):
        store = sample_store()
        pin = self.make_pin(store)
        store["keys"][0]["trust_basis_reference"] = "different-reference"
        self.assertEqual(verify_trust_store_pin(store, pin)["trust_policy_pin"], "MISMATCH")

    def test_empty_store_can_be_pinned_without_authorising_keys(self):
        store = {"record_version": "audit-trust-store/v1", "keys": []}
        self.assertEqual(verify_trust_store_pin(store, self.make_pin(store))["trust_policy_pin"], "MATCH")

    def test_object_key_order_does_not_change_canonical_digest(self):
        store = sample_store()
        reversed_store = {
            "keys": [{key: value for key, value in reversed(list(store["keys"][0].items()))}],
            "record_version": store["record_version"],
        }
        self.assertEqual(canonical_trust_store_bytes(store), canonical_trust_store_bytes(reversed_store))

    def test_malformed_pin_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, "64 lowercase hexadecimal"):
            verify_trust_store_pin(sample_store(), {
                "sha256": "A" * 64,
                "source_reference": "operator://pin",
            })

    def test_pin_unknown_fields_rejected(self):
        store = sample_store()
        pin = self.make_pin(store)
        pin["trusted"] = True
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            verify_trust_store_pin(store, pin)

    def test_invalid_trust_store_rejected_before_comparison(self):
        store = sample_store()
        store["keys"][0]["status"] = "TRUSTED"
        with self.assertRaisesRegex(ValueError, "status must be"):
            verify_trust_store_pin(store, self.make_pin(sample_store()))


if __name__ == "__main__":
    unittest.main()
