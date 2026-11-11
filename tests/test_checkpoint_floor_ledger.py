"""Tests for the append-only checkpoint rollback-floor ledger."""
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from experiments.audit_event_chain import append_audit_event
from experiments.checkpoint_recovery import _canonical_checkpoint_sha256
from experiments.checkpoint_floor_ledger import (
    CheckpointFloorDurabilityUncertain,
    append_checkpoint_floor,
    checkpoint_floor_value,
    classify_checkpoint_recovery_with_floor_ledger,
    load_checkpoint_floor_ledger,
)


def _append_floor_from_process(path, sequence, result_queue):
    try:
        result_queue.put(
            append_checkpoint_floor(
                path,
                sequence,
                f"2026-11-11T10:00:{sequence:02d}Z",
            )
        )
    except ValueError:
        result_queue.put("REJECTED_AS_STALE")


class CheckpointFloorLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "checkpoint-floor.jsonl"

    def _recovery_fixture(self):
        events = []
        for event_id, event_type, timestamp in (
            ("reg-1", "REGISTRATION_FROZEN", "2026-11-11T09:00:00Z"),
            ("access-1", "OUTCOME_ACCESS", "2026-11-11T09:01:00Z"),
            ("analysis-1", "ANALYSIS_STARTED", "2026-11-11T09:02:00Z"),
        ):
            events = append_audit_event(
                events,
                event_id=event_id,
                event_type=event_type,
                occurred_at_utc=timestamp,
                actor_reference="operator:test",
                evidence_reference="evidence:test",
            )
        checkpoint = {
            "record_version": "audit-chain-checkpoint/v1",
            "registration_event_id": "reg-1",
            "checkpoint_sequence": 2,
            "checkpoint_event_sha256": events[2]["event_sha256"],
            "anchored_at_utc": "2026-11-11T09:03:00Z",
            "anchor_reference": "anchor:test:1",
        }
        receipt = {
            "record_version": "audit-checkpoint-acceptance/v1",
            "checkpoint_sequence": 2,
            "checkpoint_sha256": _canonical_checkpoint_sha256(checkpoint),
            "accepted_at_utc": "2026-11-11T09:04:00Z",
            "receipt_reference": "receipt:test:1",
        }
        return events, checkpoint, receipt

    def test_recovery_uses_floor_ledger_and_returns_provenance(self):
        events, checkpoint, receipt = self._recovery_fixture()
        append_checkpoint_floor(self.path, 3, "2026-11-11T09:05:00Z")
        result = classify_checkpoint_recovery_with_floor_ledger(
            events, checkpoint, receipt, self.path
        )
        self.assertEqual(result["recovery_status"], "BELOW_FLOOR")
        self.assertEqual(result["rollback_floor"], "BELOW_FLOOR")
        self.assertEqual(
            result["rollback_floor_source"],
            "LOCAL_APPEND_ONLY_LEDGER_NOT_AUTHENTICATED",
        )
        self.assertEqual(result["rollback_floor_revision"], 0)
        self.assertEqual(
            result["rollback_floor_entry_sha256"],
            load_checkpoint_floor_ledger(self.path)[-1]["entry_sha256"],
        )

    def test_recovery_with_matching_ledger_floor_remains_unauthenticated(self):
        events, checkpoint, receipt = self._recovery_fixture()
        append_checkpoint_floor(self.path, 2, "2026-11-11T09:05:00Z")
        result = classify_checkpoint_recovery_with_floor_ledger(
            events, checkpoint, receipt, self.path
        )
        self.assertEqual(
            result["recovery_status"], "CONSISTENT_UNAUTHENTICATED"
        )
        self.assertEqual(result["rollback_floor"], "MEETS_FLOOR")
        self.assertEqual(
            result["rollback_floor_source"],
            "LOCAL_APPEND_ONLY_LEDGER_NOT_AUTHENTICATED",
        )

    def test_recovery_does_not_default_missing_floor_ledger(self):
        events, checkpoint, receipt = self._recovery_fixture()
        with self.assertRaises(FileNotFoundError):
            classify_checkpoint_recovery_with_floor_ledger(
                events, checkpoint, receipt, self.path
            )

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


    def test_ledger_reader_uses_shared_interprocess_lock(self):
        append_checkpoint_floor(self.path, 4, "2026-11-11T10:00:00Z")
        real_flock = __import__("fcntl").flock
        lock_modes = []

        def record_flock(descriptor, operation):
            if operation == __import__("fcntl").LOCK_SH:
                lock_modes.append("SHARED")
            return real_flock(descriptor, operation)

        with mock.patch(
            "experiments.checkpoint_floor_ledger.fcntl.flock",
            side_effect=record_flock,
        ):
            self.assertEqual(checkpoint_floor_value(self.path), 4)

        self.assertEqual(lock_modes, ["SHARED"])

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

    def test_concurrent_writers_leave_one_valid_monotonic_history(self):
        def write_floor(sequence):
            try:
                return append_checkpoint_floor(
                    self.path,
                    sequence,
                    f"2026-11-11T10:00:{sequence:02d}Z",
                )
            except ValueError:
                # A higher sequence may acquire the lock first; later lower
                # candidates must then be rejected rather than appended.
                return "REJECTED_AS_STALE"

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(write_floor, range(1, 9)))

        entries = load_checkpoint_floor_ledger(self.path)
        floors = [entry["minimum_checkpoint_sequence"] for entry in entries]
        self.assertEqual(floors, sorted(floors))
        self.assertEqual(floors[-1], 8)
        self.assertEqual(
            [entry["floor_revision"] for entry in entries],
            list(range(len(entries))),
        )
        self.assertTrue(self.path.with_name(self.path.name + ".lock").exists())

    def test_append_refuses_when_interprocess_locking_is_unavailable(self):
        with mock.patch(
            "experiments.checkpoint_floor_ledger.fcntl", None
        ):
            with self.assertRaisesRegex(
                RuntimeError, "locking is unavailable"
            ):
                append_checkpoint_floor(
                    self.path, 4, "2026-11-11T10:00:00Z"
                )
        self.assertFalse(self.path.exists())
        self.assertFalse(
            self.path.with_name(self.path.name + ".lock").exists()
        )

    @unittest.skipUnless(
        hasattr(os, "O_DIRECTORY") and hasattr(multiprocessing, "get_context"),
        "POSIX process-locking test requires a fork-capable platform",
    )
    def test_separate_processes_share_one_serialized_ledger_history(self):
        context = multiprocessing.get_context("fork")
        result_queue = context.Queue()
        processes = [
            context.Process(
                target=_append_floor_from_process,
                args=(self.path, sequence, result_queue),
            )
            for sequence in range(1, 9)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
            self.assertFalse(process.is_alive(), "writer process did not finish")
            self.assertEqual(process.exitcode, 0)

        outcomes = [result_queue.get(timeout=2) for _ in processes]
        self.assertEqual(len(outcomes), 8)
        entries = load_checkpoint_floor_ledger(self.path)
        floors = [entry["minimum_checkpoint_sequence"] for entry in entries]
        self.assertEqual(floors, sorted(floors))
        self.assertEqual(floors[-1], 8)
        self.assertEqual(
            [entry["floor_revision"] for entry in entries],
            list(range(len(entries))),
        )

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

    def test_partial_append_is_uncertain_and_loader_rejects_tail(self):
        with mock.patch(
            "experiments.checkpoint_floor_ledger.os.write",
            side_effect=lambda descriptor, data: len(data) - 1,
        ):
            with self.assertRaisesRegex(
                CheckpointFloorDurabilityUncertain, "append was partial"
            ):
                append_checkpoint_floor(
                    self.path, 4, "2026-11-11T10:00:00Z"
                )
        with self.assertRaisesRegex(ValueError, "incomplete"):
            load_checkpoint_floor_ledger(self.path)

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
