"""Tests for detached RFC 3161 trust-anchor provenance attestations."""
import base64
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.trust_policy_pin import trust_store_sha256

from experiments.rfc3161_anchor_provenance import (
    canonical_provenance_payload,
    verify_timestamp_anchor_provenance,
    verify_rfc3161_timestamp_with_provenance,
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
            "authority_name": "Synthetic test authority",
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

    def verify(self, minimum_sequence=4):
        return verify_timestamp_anchor_provenance(
            self.anchor, self.attestation, self.envelope, self.store,
            at_utc="2026-11-10T13:00:00Z", minimum_sequence=minimum_sequence
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
        changed = dict(self.attestation, source_reference="tampered://reference")
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

    def test_attestation_validity_interval_includes_issue_instant(self):
        result = verify_timestamp_anchor_provenance(
            self.anchor, self.attestation, self.envelope, self.store,
            at_utc=self.attestation["issued_at_utc"], minimum_sequence=4,
        )
        self.assertEqual(
            result["provenance_verification"],
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE",
        )

    def test_attestation_validity_interval_excludes_instant_before_issue(self):
        result = verify_timestamp_anchor_provenance(
            self.anchor, self.attestation, self.envelope, self.store,
            at_utc="2026-10-31T23:59:59.999999Z", minimum_sequence=4,
        )
        self.assertEqual(result["provenance_verification"], "ATTESTATION_OUTSIDE_VALIDITY")
        self.assertEqual(result["attestation_signature"], "NOT_PERFORMED")

    def test_attestation_validity_interval_excludes_exact_expiry(self):
        result = verify_timestamp_anchor_provenance(
            self.anchor, self.attestation, self.envelope, self.store,
            at_utc=self.attestation["expires_at_utc"], minimum_sequence=4,
        )
        self.assertEqual(result["provenance_verification"], "ATTESTATION_OUTSIDE_VALIDITY")
        self.assertEqual(result["attestation_signature"], "NOT_PERFORMED")

    def test_exact_sequence_floor_is_accepted(self):
        result = self.verify(minimum_sequence=self.attestation["sequence"])
        self.assertEqual(
            result["provenance_verification"],
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE",
        )
        self.assertEqual(result["attestation_sequence"], result["minimum_sequence"])

    def test_malformed_claimed_verification_time_rejected(self):
        with self.assertRaisesRegex(ValueError, "at_utc"):
            verify_timestamp_anchor_provenance(
                self.anchor, self.attestation, self.envelope, self.store,
                at_utc="not-a-clock", minimum_sequence=4,
            )

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


    def test_composite_verification_checks_provenance_before_timestamp(self):
        from unittest.mock import patch
        with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp") as timestamp:
            timestamp.return_value = {"timestamp_verification": "VALID", "message_imprint": "MATCH"}
            result = verify_rfc3161_timestamp_with_provenance(
                b"token", b"payload", self.anchor,
                {"sha256": hashlib.sha256(self.anchor).hexdigest(), "source_reference": "operator pin"},
                self.attestation, self.envelope, self.store,
                at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
            )
        self.assertEqual(result["combined_verification"], "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE")
        self.assertEqual(result["governance_authentication"], "NOT_ESTABLISHED")
        timestamp.assert_called_once()

    def test_composite_verification_never_checks_timestamp_after_provenance_failure(self):
        from unittest.mock import patch
        bad_anchor = self.anchor + b"changed"
        with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp") as timestamp:
            result = verify_rfc3161_timestamp_with_provenance(
                b"token", b"payload", bad_anchor,
                {"sha256": hashlib.sha256(bad_anchor).hexdigest(), "source_reference": "operator pin"},
                self.attestation, self.envelope, self.store,
                at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
            )
        self.assertEqual(result["combined_verification"], "PROVENANCE_NOT_VERIFIED")
        self.assertEqual(result["timestamp_evidence"]["timestamp_verification"], "NOT_PERFORMED")
        timestamp.assert_not_called()


    def test_optional_governance_store_pin_must_match_before_signature(self):
        pin = {
            "sha256": "0" * 64,
            "source_reference": "independently-held synthetic pin",
        }
        result = verify_timestamp_anchor_provenance(
            self.anchor, self.attestation, self.envelope, self.store,
            at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
            trust_store_pin=pin,
        )
        self.assertEqual(result["provenance_verification"], "GOVERNANCE_POLICY_PIN_MISMATCH")
        self.assertEqual(result["attestation_signature"], "NOT_PERFORMED")

    def test_matching_governance_store_pin_is_reported_without_authenticating_source(self):
        pin = {
            "sha256": trust_store_sha256(self.store),
            "source_reference": "independently-held synthetic pin",
        }
        result = verify_timestamp_anchor_provenance(
            self.anchor, self.attestation, self.envelope, self.store,
            at_utc="2026-11-10T13:00:00Z", minimum_sequence=4,
            trust_store_pin=pin,
        )
        self.assertEqual(result["provenance_verification"], "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE")
        self.assertEqual(result["governance_trust_store_pin"]["trust_policy_pin"], "MATCH")
        self.assertEqual(result["governance_trust_store_pin"]["pin_source_authentication"], "NOT_INDEPENDENTLY_AUTHENTICATED")


if __name__ == "__main__":
    unittest.main()
