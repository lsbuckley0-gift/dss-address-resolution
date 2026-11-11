"""Tests for the append-only checkpoint rollback-floor ledger."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from experiments.checkpoint_floor_ledger import (
    CheckpointFloorDurabilityUncertain,
    append_checkpoint_floor,
    checkpoint_floor_value,
    load_checkpoint_floor_ledger,
)


class CheckpointFloorLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "checkpoint-floor.jsonl"

    def test_first_entry_establishes_floor(self):
        result = append_checkpoint_floor(
            self.path, 4, "2026-11-11T10:00:00Z"
        )
        self.assertEqual(result["append"], "APPENDED")
        self.assertEqual(result["floor_revision"], 0)
        self.assertEqual(result["file_fsync"], "CONFIRMED")
        self.assertEqual(
            result["directory_fsync"],
            "CONFIRMED" if hasattr(os, "O_DIRECTORY") else "UNAVAILABLE",
        )
        self.assertEqual(checkpoint_floor_value(self.path), 4)

    def test_floor_advances_and_forms_digest_chain(self):
        append_checkpoint_floor(self.path, 4, "2026-11-11T10:00:00Z")
        append_checkpoint_floor(self.path, 7, "2026-11-11T10:01:00Z")
        entries = load_checkpoint_floor_ledger(self.path)
        self.assertEqual([entry["floor_revision"] for entry in entries], [0, 1])
        self.assertEqual(entries[1]["previous_entry_sha256"], entries[0]["entry_sha256"])
        self.assertEqual(checkpoint_floor_value(self.path), 7)

    def test_lower_floor_is_rejected_without_changing_ledger(self):
        append_checkpoint_floor(self.path, 7, "2026-11-11T10:00:00Z")
        previous = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "floor regression refused"):
            append_checkpoint_floor(self.path, 6, "2026-11-11T10:01:00Z")
        self.assertEqual(self.path.read_bytes(), previous)

    def test_identical_floor_retry_reconfirms_fsync_without_duplicate(self):
        append_checkpoint_floor(self.path, 7, "2026-11-11T10:00:00Z")
        previous = self.path.read_bytes()
        with mock.patch(
            "experiments.checkpoint_floor_ledger.os.fsync",
            side_effect=OSError("injected"),
        ):
            with self.assertRaises(CheckpointFloorDurabilityUncertain):
                append_checkpoint_floor(self.path, 7, "2026-11-11T10:01:00Z")
        result = append_checkpoint_floor(self.path, 7, "2026-11-11T10:01:00Z")
        self.assertEqual(result["append"], "NOT_REQUIRED_IDENTICAL_FLOOR")
        self.assertEqual(result["file_fsync"], "CONFIRMED")
        self.assertEqual(
            result["directory_fsync"],
            "CONFIRMED" if hasattr(os, "O_DIRECTORY") else "UNAVAILABLE",
        )
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(len(load_checkpoint_floor_ledger(self.path)), 1)

    @unittest.skipUnless(
        hasattr(os, "O_DIRECTORY"),
        "parent-directory fsync is unavailable on this platform",
    )
    def test_directory_fsync_failure_is_uncertain_and_retry_reconfirms(self):
        with mock.patch(
            "experiments.checkpoint_floor_ledger.os.fsync",
            side_effect=[None, OSError("injected directory fsync failure")],
        ):
            with self.assertRaises(CheckpointFloorDurabilityUncertain):
                append_checkpoint_floor(
                    self.path, 5, "2026-11-11T10:00:00Z"
                )
        self.assertEqual(checkpoint_floor_value(self.path), 5)
        result = append_checkpoint_floor(
            self.path, 5, "2026-11-11T10:01:00Z"
        )
        self.assertEqual(result["append"], "NOT_REQUIRED_IDENTICAL_FLOOR")
        self.assertEqual(result["directory_fsync"], "CONFIRMED")
        self.assertEqual(len(load_checkpoint_floor_ledger(self.path)), 1)

    def test_timestamp_regression_is_rejected(self):
        append_checkpoint_floor(self.path, 4, "2026-11-11T10:01:00Z")
        with self.assertRaisesRegex(ValueError, "timestamp regression refused"):
            append_checkpoint_floor(self.path, 5, "2026-11-11T10:00:00Z")

    def test_invalid_floor_values_are_rejected(self):
        for invalid in (-1, True, 1.5, "4"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "non-negative integer"):
                    append_checkpoint_floor(
                        self.path, invalid, "2026-11-11T10:00:00Z"
                    )
        self.assertFalse(self.path.exists())

    def test_digest_tampering_fails_closed(self):
        append_checkpoint_floor(self.path, 4, "2026-11-11T10:00:00Z")
        entry = json.loads(self.path.read_text(encoding="utf-8"))
        entry["minimum_checkpoint_sequence"] = 1
        self.path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            checkpoint_floor_value(self.path)

    def test_incomplete_tail_fails_closed(self):
        append_checkpoint_floor(self.path, 4, "2026-11-11T10:00:00Z")
        with self.path.open("ab") as stream:
            stream.write(b'{"partial":')
        with self.assertRaisesRegex(ValueError, "incomplete"):
            load_checkpoint_floor_ledger(self.path)

    def test_missing_or_empty_ledger_never_defaults_to_zero(self):
        with self.assertRaises(FileNotFoundError):
            checkpoint_floor_value(self.path)
        self.path.touch()
        with self.assertRaisesRegex(ValueError, "contains no complete entries"):
            checkpoint_floor_value(self.path)


if __name__ == "__main__":
    unittest.main()
