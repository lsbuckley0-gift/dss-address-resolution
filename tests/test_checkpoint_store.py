"""Tests for atomic single-file checkpoint envelope persistence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from experiments.checkpoint_recovery import _canonical_checkpoint_sha256
from experiments.checkpoint_store import (
    CheckpointEnvelopeDurabilityUncertain,
    build_checkpoint_envelope,
    load_checkpoint_envelope,
    write_checkpoint_envelope,
)


class CheckpointStoreTests(unittest.TestCase):
    def setUp(self):
        self.checkpoint = {
            "record_version": "audit-chain-checkpoint/v1",
            "registration_event_id": "reg-1",
            "checkpoint_sequence": 2,
            "checkpoint_event_sha256": "a" * 64,
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
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "checkpoint-envelope.json"

    def test_build_envelope_keeps_payload_and_receipt_together(self):
        envelope = build_checkpoint_envelope(self.checkpoint, self.receipt)
        self.assertEqual(
            envelope["record_version"], "audit-checkpoint-acceptance-envelope/v1"
        )
        self.assertEqual(envelope["checkpoint"], self.checkpoint)
        self.assertEqual(envelope["acceptance_receipt"], self.receipt)

    def test_write_and_load_round_trip_one_envelope(self):
        result = write_checkpoint_envelope(self.path, self.checkpoint, self.receipt)
        loaded = load_checkpoint_envelope(self.path)
        self.assertEqual(loaded["checkpoint"], self.checkpoint)
        self.assertEqual(loaded["acceptance_receipt"], self.receipt)
        self.assertEqual(result["replacement"], "ATOMIC_SAME_DIRECTORY_REPLACE")
        self.assertEqual(result["file_fsync"], "CONFIRMED")
        self.assertEqual(result["storage_atomicity"], "SINGLE_ENVELOPE_ONLY")
        self.assertEqual(result["rollback_floor_protection"], "NOT_PROVIDED")

    def test_receipt_digest_mismatch_is_rejected_before_write(self):
        changed = dict(self.receipt, checkpoint_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            write_checkpoint_envelope(self.path, self.checkpoint, changed)
        self.assertFalse(self.path.exists())


    def test_invalid_checkpoint_identity_fields_are_rejected(self):
        changed = dict(self.checkpoint, registration_event_id=" ")
        with self.assertRaisesRegex(ValueError, "registration_event_id"):
            build_checkpoint_envelope(changed, self.receipt)
        changed = dict(self.checkpoint, checkpoint_event_sha256="A" * 64)
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            build_checkpoint_envelope(changed, self.receipt)

    def test_receipt_sequence_mismatch_is_rejected(self):
        changed = dict(self.receipt, checkpoint_sequence=3)
        with self.assertRaisesRegex(ValueError, "sequence does not match"):
            build_checkpoint_envelope(self.checkpoint, changed)

    def test_receipt_before_checkpoint_is_rejected(self):
        changed = dict(self.receipt, accepted_at_utc="2026-11-10T10:02:00Z")
        with self.assertRaisesRegex(ValueError, "precedes checkpoint"):
            build_checkpoint_envelope(self.checkpoint, changed)

    def test_lower_sequence_cannot_replace_newer_envelope(self):
        write_checkpoint_envelope(self.path, self.checkpoint, self.receipt)
        previous = self.path.read_bytes()
        older_checkpoint = dict(self.checkpoint, checkpoint_sequence=1)
        older_receipt = dict(
            self.receipt,
            checkpoint_sequence=1,
            checkpoint_sha256=_canonical_checkpoint_sha256(older_checkpoint),
        )
        with self.assertRaisesRegex(ValueError, "sequence regression refused"):
            write_checkpoint_envelope(self.path, older_checkpoint, older_receipt)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(
            sorted(p.name for p in Path(self.tempdir.name).iterdir()),
            ["checkpoint-envelope.json"],
        )

    def test_same_sequence_with_different_content_is_rejected(self):
        write_checkpoint_envelope(self.path, self.checkpoint, self.receipt)
        previous = self.path.read_bytes()
        changed_checkpoint = dict(self.checkpoint, anchor_reference="anchor:other")
        changed_receipt = dict(
            self.receipt,
            checkpoint_sha256=_canonical_checkpoint_sha256(changed_checkpoint),
        )
        with self.assertRaisesRegex(ValueError, "same checkpoint sequence"):
            write_checkpoint_envelope(self.path, changed_checkpoint, changed_receipt)
        self.assertEqual(self.path.read_bytes(), previous)

    def test_identical_same_sequence_retry_is_idempotent(self):
        write_checkpoint_envelope(self.path, self.checkpoint, self.receipt)
        previous = self.path.read_bytes()
        result = write_checkpoint_envelope(self.path, self.checkpoint, self.receipt)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(result["replacement"], "NOT_REQUIRED_IDENTICAL_ENVELOPE")
        self.assertEqual(result["file_fsync"], "NOT_PERFORMED")

    def test_failed_replace_preserves_previous_envelope_and_cleans_temp(self):
        write_checkpoint_envelope(self.path, self.checkpoint, self.receipt)
        previous = self.path.read_bytes()
        changed_checkpoint = dict(self.checkpoint, checkpoint_sequence=3)
        changed_receipt = dict(
            self.receipt,
            checkpoint_sequence=3,
            checkpoint_sha256=_canonical_checkpoint_sha256(changed_checkpoint),
        )
        with mock.patch("experiments.checkpoint_store.os.replace", side_effect=OSError("injected")):
            with self.assertRaisesRegex(OSError, "injected"):
                write_checkpoint_envelope(self.path, changed_checkpoint, changed_receipt)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(
            sorted(p.name for p in Path(self.tempdir.name).iterdir()),
            ["checkpoint-envelope.json"],
        )


    def test_file_fsync_failure_preserves_previous_envelope_and_cleans_temp(self):
        write_checkpoint_envelope(self.path, self.checkpoint, self.receipt)
        previous = self.path.read_bytes()
        changed_checkpoint = dict(self.checkpoint, checkpoint_sequence=3)
        changed_receipt = dict(
            self.receipt,
            checkpoint_sequence=3,
            checkpoint_sha256=_canonical_checkpoint_sha256(changed_checkpoint),
        )
        with mock.patch("experiments.checkpoint_store.os.fsync", side_effect=OSError("injected file fsync failure")):
            with self.assertRaisesRegex(OSError, "injected file fsync failure"):
                write_checkpoint_envelope(self.path, changed_checkpoint, changed_receipt)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(
            sorted(p.name for p in Path(self.tempdir.name).iterdir()),
            ["checkpoint-envelope.json"],
        )

    @unittest.skipUnless(hasattr(os, "O_DIRECTORY"), "POSIX directory fsync unavailable")
    def test_directory_fsync_failure_reports_uncertain_after_visible_replace(self):
        calls = 0
        real_fsync = os.fsync

        def fail_second_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected directory fsync failure")
            return real_fsync(fd)

        with mock.patch("experiments.checkpoint_store.os.fsync", side_effect=fail_second_fsync):
            with self.assertRaises(CheckpointEnvelopeDurabilityUncertain):
                write_checkpoint_envelope(self.path, self.checkpoint, self.receipt)
        self.assertTrue(self.path.exists())
        loaded = load_checkpoint_envelope(self.path)
        self.assertEqual(loaded["checkpoint"], self.checkpoint)
        self.assertEqual(calls, 2)

    def test_loader_rejects_truncated_or_incomplete_envelope(self):
        self.path.write_text(
            json.dumps({
                "record_version": "audit-checkpoint-acceptance-envelope/v1",
                "checkpoint": self.checkpoint,
            }),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "missing field"):
            load_checkpoint_envelope(self.path)


if __name__ == "__main__":
    unittest.main()
