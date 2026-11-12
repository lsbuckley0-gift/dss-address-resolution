"""Tests for the durable resumable recovery-operation journal."""
import hashlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from experiments.recovery_operation_journal import (
    begin_or_resume_recovery, complete_recovery, inspect_recovery_operations,
)


class RecoveryOperationJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "recovery.jsonl"
        self.request = hashlib.sha256(b"canonical recovery request").hexdigest()
        self.result = hashlib.sha256(b"recovery result").hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def begin(self, operation_id="op-001", **overrides):
        args = {"operation_id": operation_id, "attestation_id": "attestation-7",
                "attestation_sequence": 7, "request_sha256": self.request}
        args.update(overrides)
        return begin_or_resume_recovery(self.path, **args)

    def test_new_operation_records_reserved_then_running(self):
        result = self.begin()
        self.assertEqual(result["operation_status"], "STARTED")
        self.assertEqual(result["entry"]["state"], "RUNNING")
        self.assertEqual(result["entry"]["event_sequence"], 2)

    def test_interrupted_running_operation_resumes_without_new_sequence(self):
        self.begin()
        resumed = self.begin()
        self.assertEqual(resumed["operation_status"], "RESUME_REQUIRED")
        self.assertTrue(resumed["resumed"])
        latest = inspect_recovery_operations(self.path)["op-001"]
        self.assertEqual(latest["attestation_sequence"], 7)
        self.assertEqual(latest["event_sequence"], 2)

    def test_operation_id_cannot_be_rebound(self):
        self.begin()
        with self.assertRaisesRegex(ValueError, "reused with different inputs"):
            self.begin(attestation_sequence=8)

    def test_completion_is_idempotent(self):
        self.begin()
        first = complete_recovery(self.path, operation_id="op-001", result_sha256=self.result)
        second = complete_recovery(self.path, operation_id="op-001", result_sha256=self.result)
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["entry"]["state"], "COMPLETED")

    def test_conflicting_completion_is_rejected(self):
        self.begin()
        complete_recovery(self.path, operation_id="op-001", result_sha256=self.result)
        other = hashlib.sha256(b"different result").hexdigest()
        with self.assertRaisesRegex(ValueError, "different result digest"):
            complete_recovery(self.path, operation_id="op-001", result_sha256=other)

    def test_concurrent_begin_requests_create_one_operation(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.begin(), range(8)))
        statuses = [r["operation_status"] for r in results]
        self.assertEqual(statuses.count("STARTED"), 1)
        self.assertEqual(statuses.count("RESUME_REQUIRED"), 7)
        self.assertEqual(inspect_recovery_operations(self.path)["op-001"]["state"], "RUNNING")

    def test_corrupted_hash_chain_fails_closed(self):
        self.begin()
        raw = self.path.read_text()
        self.path.write_text(raw.replace('"state":"RUNNING"', '"state":"COMPLETED"', 1))
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            inspect_recovery_operations(self.path)

    def test_boolean_sequence_rejected(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            self.begin(attestation_sequence=True)

    def test_completion_requires_known_operation(self):
        with self.assertRaisesRegex(ValueError, "unknown recovery operation"):
            complete_recovery(self.path, operation_id="missing", result_sha256=self.result)


if __name__ == "__main__":
    unittest.main()
