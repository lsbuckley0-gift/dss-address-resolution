"""Tests for the durable resumable recovery-operation journal."""
import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from pathlib import Path
from experiments.recovery_operation_journal import (
    begin_or_resume_recovery, complete_recovery, inspect_recovery_operations,
)


def _begin_in_subprocess(path, request_sha256):
    return begin_or_resume_recovery(
        path,
        operation_id="op-process",
        attestation_id="attestation-7",
        attestation_sequence=7,
        request_sha256=request_sha256,
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

    def test_attestation_sequence_cannot_be_rebound_to_another_operation(self):
        self.begin(operation_id="op-001")
        with self.assertRaisesRegex(ValueError, "already bound to a different recovery operation"):
            self.begin(operation_id="op-002")
        latest = inspect_recovery_operations(self.path)
        self.assertEqual(set(latest), {"op-001"})
        self.assertEqual(latest["op-001"]["state"], "RUNNING")

    def test_concurrent_operations_cannot_claim_the_same_attestation_sequence(self):
        def attempt(index):
            try:
                return self.begin(operation_id=f"op-{index:03d}")["operation_status"]
            except ValueError:
                return "REJECTED"

        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(attempt, range(8)))
        self.assertEqual(statuses.count("STARTED"), 1)
        self.assertEqual(statuses.count("REJECTED"), 7)
        self.assertEqual(len(inspect_recovery_operations(self.path)), 1)

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

    def test_concurrent_processes_create_one_operation(self):
        with ProcessPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(
                _begin_in_subprocess,
                [str(self.path)] * 4,
                [self.request] * 4,
            ))
        statuses = [result["operation_status"] for result in results]
        self.assertEqual(statuses.count("STARTED"), 1)
        self.assertEqual(statuses.count("RESUME_REQUIRED"), 3)
        latest = inspect_recovery_operations(self.path)["op-process"]
        self.assertEqual(latest["state"], "RUNNING")
        self.assertEqual(latest["event_sequence"], 2)

    def test_corrupted_hash_chain_fails_closed(self):
        self.begin()
        raw = self.path.read_text()
        self.path.write_text(raw.replace('"state":"RUNNING"', '"state":"COMPLETED"', 1))
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            inspect_recovery_operations(self.path)

    def test_boolean_event_sequence_fails_closed(self):
        self.begin()
        raw = self.path.read_text()
        self.path.write_text(raw.replace('"event_sequence":1', '"event_sequence":true', 1))
        with self.assertRaisesRegex(ValueError, "invalid or non-contiguous sequence"):
            inspect_recovery_operations(self.path)

    def test_float_event_sequence_fails_closed(self):
        self.begin()
        raw = self.path.read_text()
        self.path.write_text(raw.replace('"event_sequence":1', '"event_sequence":1.0', 1))
        with self.assertRaisesRegex(ValueError, "invalid or non-contiguous sequence"):
            inspect_recovery_operations(self.path)

    def test_duplicate_json_keys_fail_closed(self):
        self.begin()
        raw = self.path.read_text()
        self.path.write_text(raw.replace('"state":"RUNNING"', '"state":"RUNNING","state":"COMPLETED"', 1))
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            inspect_recovery_operations(self.path)

    def test_incomplete_final_record_fails_closed(self):
        self.begin()
        raw = self.path.read_text()
        self.path.write_text(raw.rstrip("\n"))
        with self.assertRaisesRegex(ValueError, "incomplete.*newline terminator"):
            inspect_recovery_operations(self.path)

    def test_non_standard_json_constant_fails_closed(self):
        self.begin()
        raw = self.path.read_text()
        self.path.write_text(raw.replace('"result_sha256":null', '"result_sha256":NaN', 1))
        with self.assertRaisesRegex(ValueError, "non-standard JSON constant"):
            inspect_recovery_operations(self.path)

    def test_non_string_state_fails_closed(self):
        self.begin()
        records = [json.loads(line) for line in self.path.read_text().splitlines()]
        records[0]["state"] = []
        payload = {key: value for key, value in records[0].items() if key != "entry_sha256"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
        records[0]["entry_sha256"] = hashlib.sha256(canonical).hexdigest()
        self.path.write_text("\\n".join(
            json.dumps(record, sort_keys=True, separators=(",", ":"))
            for record in records
        ) + "\\n")
        with self.assertRaisesRegex(ValueError, "invalid state"):
            inspect_recovery_operations(self.path)

    def test_boolean_sequence_rejected(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            self.begin(attestation_sequence=True)

    def test_completion_requires_known_operation(self):
        with self.assertRaisesRegex(ValueError, "unknown recovery operation"):
            complete_recovery(self.path, operation_id="missing", result_sha256=self.result)


if __name__ == "__main__":
    unittest.main()
