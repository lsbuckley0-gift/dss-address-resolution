"""Tests for the operation-bound independent recovery sequence contract."""
import hashlib
import unittest

from experiments.recovery_sequence_contract import (
    RecoverySequenceBinding,
    SequenceConsumptionOutcome,
    SequenceConsumptionResult,
    consume_or_reconcile_sequence,
    query_sequence_consumption,
)


class FakeSequenceService:
    """Test double only; it is not a production durability implementation."""

    def __init__(self, consume_result=None, query_result=None, consume_error=None,
                 query_error=None):
        self.consume_result = consume_result
        self.query_result = query_result
        self.consume_error = consume_error
        self.query_error = query_error
        self.consume_calls = []
        self.query_calls = []

    def consume(self, binding):
        self.consume_calls.append(binding)
        if self.consume_error:
            raise self.consume_error
        return self.consume_result

    def query(self, binding):
        self.query_calls.append(binding)
        if self.query_error:
            raise self.query_error
        return self.query_result


class RecoverySequenceContractTests(unittest.TestCase):
    def setUp(self):
        self.binding = RecoverySequenceBinding(
            operation_id="op-001",
            attestation_id="attestation-7",
            attestation_sequence=7,
            request_sha256=hashlib.sha256(b"canonical request").hexdigest(),
        )

    def result(self, outcome, binding=None):
        return SequenceConsumptionResult(
            binding or self.binding, outcome
        )

    def test_binding_rejects_boolean_sequence(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            RecoverySequenceBinding("op-001", "attestation-7", True,
                                    self.binding.request_sha256)

    def test_binding_rejects_malformed_request_digest(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            RecoverySequenceBinding("op-001", "attestation-7", 7, "not-a-digest")

    def test_result_requires_typed_outcome(self):
        with self.assertRaisesRegex(ValueError, "explicit SequenceConsumptionOutcome"):
            SequenceConsumptionResult(self.binding, "CONSUMED")

    def test_consume_returns_operation_bound_consumed_result(self):
        expected = self.result(SequenceConsumptionOutcome.CONSUMED)
        service = FakeSequenceService(consume_result=expected)
        actual = consume_or_reconcile_sequence(service, self.binding)
        self.assertEqual(actual, expected)
        self.assertEqual(service.consume_calls, [self.binding])
        self.assertEqual(service.query_calls, [])

    def test_consume_exception_queries_same_full_binding(self):
        expected = self.result(SequenceConsumptionOutcome.CONSUMED)
        service = FakeSequenceService(
            consume_error=OSError("connection lost after commit"),
            query_result=expected,
        )
        actual = consume_or_reconcile_sequence(service, self.binding)
        self.assertEqual(actual, expected)
        self.assertEqual(service.consume_calls, [self.binding])
        self.assertEqual(service.query_calls, [self.binding])

    def test_query_failure_is_indeterminate_not_consumed(self):
        service = FakeSequenceService(
            consume_error=OSError("connection lost"),
            query_error=TimeoutError("query unavailable"),
        )
        actual = consume_or_reconcile_sequence(service, self.binding)
        self.assertEqual(actual.binding, self.binding)
        self.assertEqual(actual.outcome, SequenceConsumptionOutcome.INDETERMINATE)

    def test_query_reports_not_consumed_for_exact_binding(self):
        expected = self.result(SequenceConsumptionOutcome.NOT_CONSUMED)
        service = FakeSequenceService(query_result=expected)
        self.assertEqual(query_sequence_consumption(service, self.binding), expected)

    def test_mismatched_operation_result_fails_closed(self):
        other = RecoverySequenceBinding(
            operation_id="op-002",
            attestation_id="attestation-7",
            attestation_sequence=7,
            request_sha256=self.binding.request_sha256,
        )
        service = FakeSequenceService(
            consume_result=self.result(SequenceConsumptionOutcome.CONSUMED, other)
        )
        with self.assertRaisesRegex(ValueError, "different recovery operation"):
            consume_or_reconcile_sequence(service, self.binding)

    def test_untyped_service_result_fails_closed(self):
        service = FakeSequenceService(consume_result={"outcome": "CONSUMED"})
        with self.assertRaisesRegex(ValueError, "untyped consumption result"):
            consume_or_reconcile_sequence(service, self.binding)


if __name__ == "__main__":
    unittest.main()
