"""Tests for detached RFC 3161 trust-anchor provenance attestations."""
import base64
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.rfc3161_anchor_provenance import (
    canonical_provenance_payload,
    verify_timestamp_anchor_provenance,
)


class TimestampAnchorProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.anchor = b"-----BEGIN CERTIFICATE-----\nsynthetic-root\n-----END CERTIFICATE-----\n"
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.store = {
            "record_version": "audit-trust-store/v1",
            "keys": [{
                "key_id": "synthetic-governance",
                "authority_name": "Synthetic test authority",
                "algorithm": "Ed25519",
                "public_key_base64": base64.b64encode(public).decode(),
                "purposes": ["RFC3161_TRUST_ANCHOR_PROVENANCE"],
                "valid_from_utc": "2026-01-01T00:00:00Z",
                "valid_until_utc": "2027-01-01T00:00:00Z",
                "status": "ACTIVE",
                "trust_basis_reference": "synthetic fixture only",
            }],
        }
        self.attestation = {
            "record_version": "rfc3161-tsa-anchor-provenance/v1",
            "attestation_id": "synthetic-attestation-001",
            "authority_name": "Synthetic TSA policy authority",
            "anchor_sha256": hashlib.sha256(self.anchor).hexdigest(),
            "intended_usage": "RFC3161_TSA_TRUST_ANCHOR",
            "policy_version": "rfc3161-tsa-anchor-policy/v1",
            "sequence": 4,
            "issued_at_utc": "2026-11-01T00:00:00Z",
            "expires_at_utc": "2026-12-01T00:00:00Z",
            "source_reference": "synthetic://fixture",
        }
        signature = self.private.sign(canonical_provenance_payload(self.attestation))
        self.envelope = {
            "record_version": "rfc3161-tsa-anchor-provenance-signature/v1",
            "key_id": "synthetic-governance",
            "signature_base64": base64.b64encode(signature).decode(),
        }

    def verify(self, **kwargs):
        return verify_timestamp_anchor_provenance(
            self.anchor, self.attestation, self.envelope, self.store,
            at_utc="2026-11-10T13:00:00Z", minimum_sequence=4, **kwargs
        )

    def test_valid_signature_binds_exact_anchor_and_policy(self):
        result = self.verify()
        self.assertEqual(result["provenance_verification"], "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE")
        self.assertEqual(result["anchor_binding"], "MATCH")
        self.assertEqual(result["attestation_signature"], "VALID")
        self.assertEqual(result["authority_authentication"], "NOT_ESTABLISHED")

    def test_changed_anchor_bytes_rejected_before_signature(self):
        result = verify_timestamp_anchor_provenance(
            self.anchor + b" ", self.attestation, self.envelope, self.store,
            at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
        )
        self.assertEqual(result["provenance_verification"], "ANCHOR_DIGEST_MISMATCH")
        self.assertEqual(result["attestation_signature"], "NOT_PERFORMED")

    def test_modified_attestation_invalidates_signature(self):
        changed = dict(self.attestation, authority_name="Different authority")
        result = verify_timestamp_anchor_provenance(
            self.anchor, changed, self.envelope, self.store,
            at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
        )
        self.assertEqual(result["provenance_verification"], "INVALID_SIGNATURE")

    def test_rollback_below_operator_floor_rejected(self):
        result = self.verify()
        self.assertEqual(result["provenance_verification"], "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE")
        result = verify_timestamp_anchor_provenance(
            self.anchor, self.attestation, self.envelope, self.store,
            at_utc="2026-11-10T13:00:00Z", minimum_sequence=5,
        )
        self.assertEqual(result["provenance_verification"], "ROLLBACK_REJECTED")

    def test_expired_attestation_rejected(self):
        result = verify_timestamp_anchor_provenance(
            self.anchor, self.attestation, self.envelope, self.store,
            at_utc="2026-12-01T00:00:00Z", minimum_sequence=4,
        )
        self.assertEqual(result["provenance_verification"], "ATTESTATION_OUTSIDE_VALIDITY")

    def test_wrong_usage_rejected(self):
        changed = dict(self.attestation, intended_usage="GENERAL_CA")
        with self.assertRaisesRegex(ValueError, "intended_usage"):
            verify_timestamp_anchor_provenance(
                self.anchor, changed, self.envelope, self.store,
                at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
            )

    def test_ineligible_governance_key_fails_closed(self):
        self.store["keys"][0]["status"] = "REVOKED"
        result = self.verify()
        self.assertEqual(result["provenance_verification"], "GOVERNANCE_KEY_NOT_ELIGIBLE")
        self.assertEqual(result["attestation_signature"], "NOT_PERFORMED")

    def test_boolean_sequence_and_floor_rejected(self):
        changed = dict(self.attestation, sequence=True)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            verify_timestamp_anchor_provenance(
                self.anchor, changed, self.envelope, self.store,
                at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
            )
        with self.assertRaisesRegex(ValueError, "minimum_sequence"):
            self.verify(minimum_sequence=True)

    def test_governance_key_authority_name_must_match_attestation(self):
        changed = dict(self.attestation, authority_name="Claimed but unbound authority")
        signature = self.private.sign(canonical_provenance_payload(changed))
        envelope = dict(self.envelope, signature_base64=base64.b64encode(signature).decode())
        result = verify_timestamp_anchor_provenance(
            self.anchor, changed, envelope, self.store,
            at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
        )
        self.assertEqual(result["provenance_verification"], "GOVERNANCE_AUTHORITY_NAME_MISMATCH")
        self.assertEqual(result["attestation_signature"], "NOT_PERFORMED")

    def test_unsupported_attestation_fields_rejected(self):
        changed = dict(self.attestation, trusted=True)
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            verify_timestamp_anchor_provenance(
                self.anchor, changed, self.envelope, self.store,
                at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
            )


if __name__ == "__main__":
    unittest.main()
