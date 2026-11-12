"""Tests for the persisted-journal and operation-bound sequence resume gate."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from experiments.recovery_operation_journal import begin_or_resume_recovery, complete_recovery
from experiments.recovery_sequence_contract import (
    RecoverySequenceBinding,
    SequenceConsumptionOutcome,
    SequenceConsumptionResult,
)
from experiments.recovery_resume_gate import (
    RecoveryResumeDecision,
    evaluate_recovery_resume,
)


class RecoveryResumeGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "recovery.jsonl"
        self.binding = RecoverySequenceBinding(
            operation_id="op-001",
            attestation_id="attestation-7",
            attestation_sequence=7,
            request_sha256=hashlib.sha256(b"canonical recovery request").hexdigest(),
        )
        begin_or_resume_recovery(
            self.path,
            operation_id=self.binding.operation_id,
            attestation_id=self.binding.attestation_id,
            attestation_sequence=self.binding.attestation_sequence,
            request_sha256=self.binding.request_sha256,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def result(self, outcome, binding=None):
        return SequenceConsumptionResult(binding or self.binding, outcome)

    def test_exact_running_journal_and_consumed_binding_authorise(self):
        self.assertEqual(
            evaluate_recovery_resume(
                self.path, self.binding, self.result(SequenceConsumptionOutcome.CONSUMED)
            ),
            RecoveryResumeDecision.AUTHORISED,
        )

    def test_not_consumed_never_authorises_classification(self):
        self.assertEqual(
            evaluate_recovery_resume(
                self.path, self.binding, self.result(SequenceConsumptionOutcome.NOT_CONSUMED)
            ),
            RecoveryResumeDecision.BLOCKED_NOT_CONSUMED,
        )

    def test_indeterminate_never_authorises_classification(self):
        self.assertEqual(
            evaluate_recovery_resume(
                self.path, self.binding, self.result(SequenceConsumptionOutcome.INDETERMINATE)
            ),
            RecoveryResumeDecision.BLOCKED_INDETERMINATE,
        )

    def test_result_for_different_operation_fails_closed(self):
        other = RecoverySequenceBinding(
            "op-002", self.binding.attestation_id, self.binding.attestation_sequence,
            self.binding.request_sha256,
        )
        with self.assertRaisesRegex(ValueError, "different recovery operation"):
            evaluate_recovery_resume(
                self.path, self.binding, self.result(SequenceConsumptionOutcome.CONSUMED, other)
            )

    def test_completed_journal_entry_cannot_be_resumed(self):
        complete_recovery(
            self.path, operation_id=self.binding.operation_id,
            result_sha256=hashlib.sha256(b"result").hexdigest(),
        )
        with self.assertRaisesRegex(ValueError, "RUNNING"):
            evaluate_recovery_resume(
                self.path, self.binding, self.result(SequenceConsumptionOutcome.CONSUMED)
            )

    def test_corrupt_journal_never_authorises_resume(self):
        raw = self.path.read_text()
        self.path.write_text(raw.replace('"state":"RUNNING"', '"state":"COMPLETED"', 1))
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            evaluate_recovery_resume(
                self.path, self.binding, self.result(SequenceConsumptionOutcome.CONSUMED)
            )


if __name__ == "__main__":
    unittest.main()
