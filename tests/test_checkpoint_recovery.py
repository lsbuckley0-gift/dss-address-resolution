"""Tests for fail-closed checkpoint crash-recovery classification."""
import unittest

from experiments.audit_event_chain import append_audit_event
from experiments.checkpoint_recovery import classify_checkpoint_recovery, _canonical_checkpoint_sha256


class CheckpointRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        for event_id, event_type, timestamp in (
            ("reg-1", "REGISTRATION_FROZEN", "2026-11-10T10:00:00Z"),
            ("access-1", "OUTCOME_ACCESS", "2026-11-10T10:01:00Z"),
            ("analysis-1", "ANALYSIS_STARTED", "2026-11-10T10:02:00Z"),
        ):
            self.events = append_audit_event(
                self.events,
                event_id=event_id,
                event_type=event_type,
                occurred_at_utc=timestamp,
                actor_reference="operator:test",
                evidence_reference="evidence:test",
            )
        self.checkpoint = {
            "record_version": "audit-chain-checkpoint/v1",
            "registration_event_id": "reg-1",
            "checkpoint_sequence": 2,
            "checkpoint_event_sha256": self.events[2]["event_sha256"],
            "anchored_at_utc": "2026-11-10T10:03:00Z",
            "anchor_reference": "anchor:test:1",
        }
        self.receipt = {
            "record_version": "audit-checkpoint-acceptance/v1",
            "checkpoint_sequence": 2,
            "checkpoint_sha256": _canonical_checkpoint_sha256(self.checkpoint),
            "accepted_at_utc": "2026-11-10T10:04:00Z",
            "receipt_reference": "receipt:test:1",
        }

    def test_payload_without_receipt_is_prepared_not_accepted(self):
        result = classify_checkpoint_recovery(self.events, self.checkpoint, None)
        self.assertEqual(result["recovery_status"], "PREPARED_NOT_ACCEPTED")

    def test_receipt_without_payload_is_not_reconstructed(self):
        result = classify_checkpoint_recovery(self.events, None, self.receipt)
        self.assertEqual(result["recovery_status"], "RECEIPT_WITHOUT_PAYLOAD")

    def test_neither_copy_is_reported_as_ambiguous(self):
        result = classify_checkpoint_recovery(self.events, None, None)
        self.assertEqual(result["recovery_status"], "NO_RETAINED_STATE")

    def test_matching_pair_is_consistent_but_not_authenticated(self):
        result = classify_checkpoint_recovery(
            self.events, self.checkpoint, self.receipt, minimum_sequence=2
        )
        self.assertEqual(result["recovery_status"], "CONSISTENT_UNAUTHENTICATED")
        self.assertEqual(result["rollback_floor"], "MEETS_FLOOR")
        self.assertEqual(result["acceptance_authentication"], "NOT_VERIFIED")
        self.assertEqual(result["storage_atomicity"], "NOT_VERIFIED")

    def test_receipt_digest_mismatch_fails_closed(self):
        changed = dict(self.receipt, checkpoint_sha256="0" * 64)
        result = classify_checkpoint_recovery(self.events, self.checkpoint, changed)
        self.assertEqual(result["recovery_status"], "CONFLICT")
        self.assertFalse(result["receipt_digest_matches"])

    def test_receipt_sequence_mismatch_fails_closed(self):
        changed = dict(self.receipt, checkpoint_sequence=1)
        result = classify_checkpoint_recovery(self.events, self.checkpoint, changed)
        self.assertEqual(result["recovery_status"], "CONFLICT")
        self.assertFalse(result["receipt_sequence_matches"])

    def test_receipt_before_checkpoint_fails_closed(self):
        changed = dict(self.receipt, accepted_at_utc="2026-11-10T10:02:00Z")
        result = classify_checkpoint_recovery(self.events, self.checkpoint, changed)
        self.assertEqual(result["recovery_status"], "CONFLICT")
        self.assertEqual(result["receipt_time_order"], "PRECEDES_CHECKPOINT")

    def test_checkpoint_below_retained_floor_fails_closed(self):
        result = classify_checkpoint_recovery(
            self.events, self.checkpoint, self.receipt, minimum_sequence=3
        )
        self.assertEqual(result["recovery_status"], "BELOW_FLOOR")
        self.assertEqual(result["rollback_floor"], "BELOW_FLOOR")

    def test_invalid_floor_is_rejected(self):
        for invalid in (-1, True, 1.5, "2"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "non-negative integer"):
                    classify_checkpoint_recovery(
                        self.events, self.checkpoint, self.receipt,
                        minimum_sequence=invalid,
                    )


    def test_checkpoint_event_chain_mismatch_fails_closed(self):
        changed = dict(self.checkpoint, checkpoint_event_sha256="0" * 64)
        result = classify_checkpoint_recovery(
            self.events, changed, self.receipt
        )
        self.assertEqual(result["recovery_status"], "CONFLICT")
        self.assertEqual(result["checkpoint_binding"], "MISMATCH")

    def test_invalid_receipt_timestamp_is_rejected(self):
        changed = dict(self.receipt, accepted_at_utc="not-a-timestamp")
        with self.assertRaisesRegex(ValueError, "ISO 8601 UTC timestamp"):
            classify_checkpoint_recovery(
                self.events, self.checkpoint, changed
            )

    def test_receipt_schema_is_strict(self):
        changed = dict(self.receipt, unexpected="value")
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            classify_checkpoint_recovery(self.events, self.checkpoint, changed)


if __name__ == "__main__":
    unittest.main()
