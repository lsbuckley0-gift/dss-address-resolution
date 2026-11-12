"""Tests for signed, anti-replay independent recovery anchors."""
import base64
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.independent_recovery_anchor import (
    RECORD_VERSION, SIGNATURE_VERSION, PURPOSE,
    canonical_recovery_anchor_payload, verify_independent_recovery_anchor,
)


class IndependentRecoveryAnchorTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.store = {"record_version": "audit-trust-store/v1", "keys": [{
            "key_id": "recovery-authority-key",
            "authority_name": "Synthetic recovery authority",
            "algorithm": "Ed25519",
            "public_key_base64": base64.b64encode(public).decode(),
            "purposes": [PURPOSE],
            "valid_from_utc": "2026-01-01T00:00:00Z",
            "valid_until_utc": "2027-01-01T00:00:00Z",
            "status": "ACTIVE",
            "trust_basis_reference": "synthetic fixture only",
        }]}
        self.attestation = {
            "record_version": RECORD_VERSION,
            "attestation_id": "recovery-attestation-001",
            "authority_name": "Synthetic recovery authority",
            "sequence": 7,
            "issued_at_utc": "2026-11-01T00:00:00Z",
            "expires_at_utc": "2026-12-01T00:00:00Z",
            "anchor": {
                "record_version": "audit-independent-recovery-anchor/v1",
                "anchor_id": "anchor:primary",
                "source_reference": "synthetic://independent-vault/epoch-7",
                "minimum_pin_revision": 4,
                "minimum_witness_sequence": 19,
                "minimum_checkpoint_sequence": 27,
            },
        }
        self.envelope = {
            "record_version": SIGNATURE_VERSION,
            "key_id": "recovery-authority-key",
            "signature_base64": base64.b64encode(
                self.private.sign(canonical_recovery_anchor_payload(self.attestation))
            ).decode(),
        }

    def verify(self, **kwargs):
        return verify_independent_recovery_anchor(
            self.attestation, self.envelope, self.store,
            at_utc="2026-11-12T12:00:00Z", minimum_anchor_sequence=7, **kwargs
        )

    def test_valid_signature_binds_anchor_and_distinct_purpose(self):
        result = self.verify()
        self.assertEqual(result["anchor_verification"], "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE")
        self.assertEqual(result["attestation_signature"], "VALID")
        self.assertEqual(result["independent_recovery_anchor"]["minimum_checkpoint_sequence"], 27)
        self.assertEqual(result["authority_authentication"], "NOT_ESTABLISHED")

    def test_modified_anchor_invalidates_signature(self):
        changed = {**self.attestation, "anchor": {
            **self.attestation["anchor"], "minimum_checkpoint_sequence": 28
        }}
        result = verify_independent_recovery_anchor(
            changed, self.envelope, self.store,
            at_utc="2026-11-12T12:00:00Z", minimum_anchor_sequence=7,
        )
        self.assertEqual(result["anchor_verification"], "INVALID_SIGNATURE")

    def test_replay_below_external_sequence_floor_rejected(self):
        result = verify_independent_recovery_anchor(
            self.attestation, self.envelope, self.store,
            at_utc="2026-11-12T12:00:00Z", minimum_anchor_sequence=8,
        )
        self.assertEqual(result["anchor_verification"], "ROLLBACK_REJECTED")
        self.assertEqual(result["attestation_signature"], "NOT_PERFORMED")

    def test_wrong_key_purpose_rejected(self):
        self.store["keys"][0]["purposes"] = ["AUDIT_CHAIN_CHECKPOINT"]
        result = self.verify()
        self.assertEqual(result["anchor_verification"], "GOVERNANCE_KEY_NOT_ELIGIBLE")
        self.assertEqual(result["key_eligibility"], "PURPOSE_NOT_ALLOWED")

    def test_expired_attestation_rejected(self):
        result = verify_independent_recovery_anchor(
            self.attestation, self.envelope, self.store,
            at_utc="2026-12-01T00:00:00Z", minimum_anchor_sequence=7,
        )
        self.assertEqual(result["anchor_verification"], "ATTESTATION_OUTSIDE_VALIDITY")

    def test_boolean_sequence_and_floor_rejected(self):
        changed = {**self.attestation, "sequence": True}
        with self.assertRaisesRegex(ValueError, "positive integer"):
            verify_independent_recovery_anchor(
                changed, self.envelope, self.store,
                at_utc="2026-11-12T12:00:00Z", minimum_anchor_sequence=7,
            )
        with self.assertRaisesRegex(ValueError, "minimum_anchor_sequence"):
            self.verify(minimum_anchor_sequence=True)


if __name__ == "__main__":
    unittest.main()
