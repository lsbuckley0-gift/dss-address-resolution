"""Tests for authenticated, two-coordinate operator pin persistence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from experiments.operator_pin_store import (
    OperatorPinDurabilityUncertain,
    append_operator_pins,
    load_operator_pins,
    verify_checkpoint_floor_witness_with_operator_pins,
    classify_checkpoint_recovery_with_operator_pins,
)

KEY = b"synthetic-test-key-material-32-bytes-minimum!!"


class OperatorPinStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "operator-pins.jsonl"

    def append(self, witness=8, checkpoint=14, second=0):
        return append_operator_pins(
            self.path, KEY,
            minimum_witness_sequence=witness,
            minimum_checkpoint_sequence=checkpoint,
            recorded_at_utc=f"2026-11-12T10:00:{second:02d}Z",
        )

    def test_first_pin_authenticates_both_coordinates(self):
        result = self.append()
        self.assertEqual(result["pin_revision"], 0)
        latest = load_operator_pins(self.path, KEY)[-1]
        self.assertEqual(latest["minimum_witness_sequence"], 8)
        self.assertEqual(latest["minimum_checkpoint_sequence"], 14)

    def test_each_coordinate_is_independently_monotonic(self):
        self.append()
        with self.assertRaisesRegex(ValueError, "witness-sequence pin regression"):
            self.append(witness=7, checkpoint=14, second=1)
        with self.assertRaisesRegex(ValueError, "checkpoint-floor pin regression"):
            self.append(witness=8, checkpoint=13, second=1)
        self.assertEqual(len(load_operator_pins(self.path, KEY)), 1)

    def test_both_coordinates_advance_and_form_authenticated_chain(self):
        self.append()
        self.append(witness=9, checkpoint=15, second=1)
        entries = load_operator_pins(self.path, KEY)
        self.assertEqual([item["pin_revision"] for item in entries], [0, 1])
        self.assertEqual(entries[1]["previous_entry_sha256"],
                         __import__("hashlib").sha256(
                             json.dumps(entries[0], sort_keys=True,
                                        separators=(",", ":"), ensure_ascii=False).encode()
                         ).hexdigest())

    def test_wrong_key_and_mac_tampering_fail_closed(self):
        self.append()
        with self.assertRaisesRegex(ValueError, "HMAC authentication failed"):
            load_operator_pins(self.path, b"X" * 32)
        entry = json.loads(self.path.read_text(encoding="utf-8"))
        entry["minimum_checkpoint_sequence"] = 1
        self.path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "HMAC authentication failed"):
            load_operator_pins(self.path, KEY)

    def test_independent_minimums_reject_a_valid_stale_backup(self):
        self.append(witness=8, checkpoint=14)
        backup = self.path.read_bytes()
        self.append(witness=9, checkpoint=15, second=1)
        self.path.write_bytes(backup)
        # A valid HMAC does not reveal that this complete old backup is stale.
        self.assertEqual(load_operator_pins(self.path, KEY)[-1]["minimum_witness_sequence"], 8)
        with self.assertRaisesRegex(ValueError, "independently retained minimum_revision"):
            load_operator_pins(self.path, KEY, minimum_revision=1)
        with self.assertRaisesRegex(ValueError, "independently retained minimum_witness_sequence"):
            load_operator_pins(self.path, KEY, minimum_witness_sequence=9)
        with self.assertRaisesRegex(ValueError, "independently retained minimum_checkpoint_sequence"):
            load_operator_pins(self.path, KEY, minimum_checkpoint_sequence=15)

    def test_identical_retry_does_not_duplicate_entry(self):
        self.append()
        result = self.append(second=1)
        self.assertEqual(result["append"], "NOT_REQUIRED_IDENTICAL_PINS")
        self.assertEqual(result["authentication"], "HMAC_SHA256_VERIFIED")
        self.assertEqual(
            result["directory_fsync"],
            "CONFIRMED" if hasattr(os, "O_DIRECTORY") else "UNAVAILABLE",
        )
        self.assertEqual(len(load_operator_pins(self.path, KEY)), 1)

    def test_concurrent_writers_preserve_valid_monotonic_history(self):
        def write(pair):
            witness, checkpoint = pair
            try:
                return append_operator_pins(
                    self.path, KEY,
                    minimum_witness_sequence=witness,
                    minimum_checkpoint_sequence=checkpoint,
                    recorded_at_utc=f"2026-11-12T10:00:{witness:02d}Z",
                )
            except ValueError:
                return "STALE"
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(write, [(2, 3), (3, 4), (4, 5), (5, 6), (6, 7), (7, 8)]))
        entries = load_operator_pins(self.path, KEY)
        self.assertEqual(entries[-1]["minimum_witness_sequence"], 7)
        self.assertEqual(entries[-1]["minimum_checkpoint_sequence"], 8)
        self.assertEqual([x["pin_revision"] for x in entries],
                         list(range(len(entries))))

    def test_partial_append_fails_closed(self):
        from unittest import mock
        self.append()
        real_write = os.write
        with mock.patch("experiments.operator_pin_store.os.write",
                        side_effect=lambda fd, data: real_write(fd, data[:-1])):
            with self.assertRaises(OperatorPinDurabilityUncertain):
                self.append(witness=9, checkpoint=15, second=1)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            load_operator_pins(self.path, KEY)


    def test_witness_verification_wrapper_uses_both_authenticated_pins(self):
        from unittest import mock
        self.append(witness=8, checkpoint=14)
        with mock.patch(
            "experiments.checkpoint_floor_witness.verify_checkpoint_floor_witness_receipt",
            return_value={"witness_verification": "MOCKED"},
        ) as verifier:
            result = verify_checkpoint_floor_witness_with_operator_pins(
                {"receipt": "synthetic"},
                {"signature": "synthetic"},
                {"record_version": "synthetic"},
                self.path,
                KEY,
                at_utc="2026-11-12T10:00:00Z",
                expected_witness_id="witness:test",
                expected_provider_id="provider:test",
                expected_failure_domain_id="domain:remote",
                local_storage_domain_id="domain:local",
                minimum_pin_revision=0,
                independent_minimum_witness_sequence=8,
                independent_minimum_checkpoint_sequence=14,
            )
        self.assertEqual(
            verifier.call_args.kwargs["minimum_witness_sequence"], 8
        )
        self.assertEqual(
            verifier.call_args.kwargs["minimum_checkpoint_sequence"], 14
        )
        self.assertEqual(result["operator_pin_authentication"], "HMAC_SHA256_VERIFIED")
        self.assertEqual(result["operator_pin_rollback_guard"],
                         "INDEPENDENT_MINIMA_SUPPLIED_AND_CHECKED")
        self.assertEqual(result["operator_pin_revision"], 0)


    def test_recovery_wrapper_gates_on_authenticated_operator_pins(self):
        from unittest import mock
        self.append(witness=9, checkpoint=15)
        with mock.patch(
            "experiments.checkpoint_floor_witness.classify_checkpoint_recovery_with_witness",
            return_value={"recovery_status": "WITNESS_LOCAL_LEDGER_DIVERGENCE"},
        ) as classifier:
            result = classify_checkpoint_recovery_with_operator_pins(
                [],
                None,
                None,
                {"receipt": "synthetic"},
                {"signature": "synthetic"},
                {"record_version": "synthetic"},
                self.path.parent / "floor-ledger.jsonl",
                self.path,
                KEY,
                at_utc="2026-11-12T10:00:00Z",
                expected_witness_id="witness:test",
                expected_provider_id="provider:test",
                expected_failure_domain_id="domain:remote",
                local_storage_domain_id="domain:local",
                minimum_pin_revision=0,
                independent_minimum_witness_sequence=9,
                independent_minimum_checkpoint_sequence=15,
            )
        self.assertEqual(classifier.call_args.kwargs["minimum_witness_sequence"], 9)
        self.assertEqual(classifier.call_args.kwargs["operator_minimum_checkpoint_sequence"], 15)
        self.assertEqual(result["recovery_status"], "WITNESS_LOCAL_LEDGER_DIVERGENCE")
        self.assertEqual(result["operator_pin_rollback_guard"],
                         "INDEPENDENT_MINIMA_SUPPLIED_AND_CHECKED")


    def test_recovery_wrapper_refuses_to_run_without_independent_minima(self):
        from unittest import mock
        self.append(witness=9, checkpoint=15)
        with mock.patch(
            "experiments.checkpoint_floor_witness.classify_checkpoint_recovery_with_witness"
        ) as classifier:
            with self.assertRaisesRegex(ValueError, "recovery requires independently retained"):
                classify_checkpoint_recovery_with_operator_pins(
                    [], None, None, {"receipt": "synthetic"},
                    {"signature": "synthetic"}, {"record_version": "synthetic"},
                    self.path.parent / "floor-ledger.jsonl", self.path, KEY,
                    at_utc="2026-11-12T10:00:00Z",
                    expected_witness_id="witness:test",
                    expected_provider_id="provider:test",
                    expected_failure_domain_id="domain:remote",
                    local_storage_domain_id="domain:local",
                )
        classifier.assert_not_called()

    def test_invalid_key_and_boolean_coordinates_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            append_operator_pins(self.path, b"short",
                                 minimum_witness_sequence=1,
                                 minimum_checkpoint_sequence=0,
                                 recorded_at_utc="2026-11-12T10:00:00Z")
        with self.assertRaisesRegex(ValueError, "positive integer"):
            append_operator_pins(self.path, KEY,
                                 minimum_witness_sequence=True,
                                 minimum_checkpoint_sequence=0,
                                 recorded_at_utc="2026-11-12T10:00:00Z")
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
