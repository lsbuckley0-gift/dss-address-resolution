"""Tests for signed external checkpoint-floor witness receipts."""
import base64
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.checkpoint_floor_witness import (
    canonical_witness_payload, verify_checkpoint_floor_witness_receipt,
)


class CheckpointFloorWitnessTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
        )
        self.store = {
            "record_version": "audit-trust-store/v1",
            "keys": [{
                "key_id": "witness-governance-key",
                "authority_name": "Synthetic witness authority",
                "algorithm": "Ed25519",
                "public_key_base64": base64.b64encode(public).decode(),
                "purposes": ["CHECKPOINT_FLOOR_WITNESS"],
                "valid_from_utc": "2026-01-01T00:00:00Z",
                "valid_until_utc": "2027-01-01T00:00:00Z",
                "status": "ACTIVE",
                "trust_basis_reference": "synthetic test fixture only",
            }],
        }
        self.receipt = {
            "record_version": "audit-checkpoint-floor-witness/v1",
            "witness_id": "witness-east-1",
            "provider_id": "provider-independent",
            "failure_domain_id": "provider-control-plane-east",
            "authority_name": "Synthetic witness authority",
            "witness_sequence": 8,
            "minimum_checkpoint_sequence": 14,
            "previous_receipt_sha256": hashlib.sha256(b"prior receipt").hexdigest(),
            "issued_at_utc": "2026-11-11T10:00:00Z",
            "expires_at_utc": "2026-11-12T10:00:00Z",
        }
        self.envelope = {
            "record_version": "audit-checkpoint-floor-witness-signature/v1",
            "key_id": "witness-governance-key",
            "signature_base64": base64.b64encode(
                self.private.sign(canonical_witness_payload(self.receipt))
            ).decode(),
        }

    def verify(self, **overrides):
        args = {
            "at_utc": "2026-11-11T11:00:00Z",
            "expected_witness_id": "witness-east-1",
            "expected_provider_id": "provider-independent",
            "expected_failure_domain_id": "provider-control-plane-east",
            "local_storage_domain_id": "local-disk-a",
            "minimum_witness_sequence": 8,
            "minimum_checkpoint_sequence": 14,
        }
        args.update(overrides)
        return verify_checkpoint_floor_witness_receipt(
            self.receipt, self.envelope, self.store, **args
        )

    def test_valid_receipt_binds_identity_sequence_and_floor(self):
        result = self.verify()
        self.assertEqual(
            result["witness_verification"],
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_AND_DOMAIN_CONFIGURATION",
        )
        self.assertEqual(result["signature_verification"], "VALID")
        self.assertEqual(
            result["failure_domain_separation"],
            "DECLARED_DISTINCT_NOT_INDEPENDENTLY_PROVEN",
        )
        self.assertEqual(result["authority_authentication"], "NOT_ESTABLISHED")

    def test_same_failure_domain_is_not_independent(self):
        result = self.verify(local_storage_domain_id="provider-control-plane-east")
        self.assertEqual(result["witness_verification"], "SAME_FAILURE_DOMAIN")
        self.assertEqual(result["signature_verification"], "NOT_PERFORMED")

    def test_unexpected_provider_or_domain_is_rejected(self):
        self.assertEqual(
            self.verify(expected_provider_id="other-provider")["witness_verification"],
            "IDENTITY_MISMATCH",
        )
        self.assertEqual(
            self.verify(expected_failure_domain_id="other-domain")["witness_verification"],
            "IDENTITY_MISMATCH",
        )

    def test_stale_witness_sequence_is_rejected(self):
        self.assertEqual(
            self.verify(minimum_witness_sequence=9)["witness_verification"],
            "ROLLBACK_REJECTED",
        )

    def test_witness_floor_below_required_checkpoint_floor_is_rejected(self):
        self.assertEqual(
            self.verify(minimum_checkpoint_sequence=15)["witness_verification"],
            "ROLLBACK_REJECTED",
        )

    def test_modified_receipt_invalidates_signature(self):
        changed = dict(self.receipt, minimum_checkpoint_sequence=15)
        result = verify_checkpoint_floor_witness_receipt(
            changed, self.envelope, self.store,
            at_utc="2026-11-11T11:00:00Z",
            expected_witness_id="witness-east-1",
            expected_provider_id="provider-independent",
            expected_failure_domain_id="provider-control-plane-east",
            local_storage_domain_id="local-disk-a",
            minimum_witness_sequence=8, minimum_checkpoint_sequence=14,
        )
        self.assertEqual(result["witness_verification"], "INVALID_SIGNATURE")

    def test_ineligible_governance_key_fails_closed(self):
        self.store["keys"][0]["status"] = "REVOKED"
        result = self.verify()
        self.assertEqual(result["witness_verification"], "GOVERNANCE_KEY_NOT_ELIGIBLE")
        self.assertEqual(result["signature_verification"], "NOT_PERFORMED")

    def test_boolean_sequences_and_floors_are_rejected(self):
        changed = dict(self.receipt, witness_sequence=True)
        with self.assertRaisesRegex(ValueError, "witness_sequence"):
            verify_checkpoint_floor_witness_receipt(
                changed, self.envelope, self.store,
                at_utc="2026-11-11T11:00:00Z",
                expected_witness_id="witness-east-1",
                expected_provider_id="provider-independent",
                expected_failure_domain_id="provider-control-plane-east",
                local_storage_domain_id="local-disk-a",
                minimum_witness_sequence=8, minimum_checkpoint_sequence=14,
            )
        with self.assertRaisesRegex(ValueError, "minimum_witness_sequence"):
            self.verify(minimum_witness_sequence=True)

    def test_expired_receipt_is_rejected(self):
        self.assertEqual(
            self.verify(at_utc="2026-11-12T10:00:00Z")["witness_verification"],
            "RECEIPT_OUTSIDE_VALIDITY",
        )

    def test_authority_name_must_match_governance_key(self):
        changed = dict(self.receipt, authority_name="Unbound authority")
        signature = self.private.sign(canonical_witness_payload(changed))
        envelope = dict(
            self.envelope, signature_base64=base64.b64encode(signature).decode(),
        )
        result = verify_checkpoint_floor_witness_receipt(
            changed, envelope, self.store,
            at_utc="2026-11-11T11:00:00Z",
            expected_witness_id="witness-east-1",
            expected_provider_id="provider-independent",
            expected_failure_domain_id="provider-control-plane-east",
            local_storage_domain_id="local-disk-a",
            minimum_witness_sequence=8, minimum_checkpoint_sequence=14,
        )
        self.assertEqual(
            result["witness_verification"], "GOVERNANCE_AUTHORITY_NAME_MISMATCH",
        )
