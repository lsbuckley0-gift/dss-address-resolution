"""Tests for detached Ed25519 checkpoint signature verification."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.audit_event_chain import append_audit_event
from experiments.audit_event_chain import main as audit_chain_main
from experiments.checkpoint_signature import (
    canonical_checkpoint_payload,
    verify_signed_checkpoint,
)

PURPOSE = "AUDIT_CHAIN_CHECKPOINT"


def chain(registration_event_id="reg-1"):
    events = []
    for event_id, event_type, timestamp in [
        (registration_event_id, "REGISTRATION_FROZEN", "2026-11-10T10:00:00Z"),
        ("access-1", "OUTCOME_ACCESS", "2026-11-10T10:01:00Z"),
        ("analysis-1", "ANALYSIS_STARTED", "2026-11-10T10:02:00Z"),
    ]:
        events = append_audit_event(
            events, event_id=event_id, event_type=event_type,
            occurred_at_utc=timestamp, actor_reference="actor:test",
            evidence_reference=f"evidence:{event_id}",
        )
    return events


def checkpoint_for(events):
    return {
        "record_version": "audit-chain-checkpoint/v1",
        "registration_event_id": "reg-1",
        "checkpoint_sequence": 0,
        "checkpoint_event_sha256": events[0]["event_sha256"],
        "anchored_at_utc": "2026-11-10T10:03:00Z",
        "anchor_reference": "synthetic://anchor/001",
    }


class CheckpointSignatureTests(unittest.TestCase):
    def setUp(self):
        self.events = chain()
        self.checkpoint = checkpoint_for(self.events)
        self.private_key = Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.store = {
            "record_version": "audit-trust-store/v1",
            "keys": [{
                "key_id": "synthetic-ed25519-01",
                "authority_name": "Synthetic Test Signer",
                "algorithm": "Ed25519",
                "public_key_base64": base64.b64encode(public_key).decode("ascii"),
                "purposes": [PURPOSE],
                "valid_from_utc": "2026-01-01T00:00:00Z",
                "valid_until_utc": "2027-01-01T00:00:00Z",
                "status": "ACTIVE",
                "trust_basis_reference": "synthetic://test-policy",
            }],
        }
        self.envelope = self.sign(self.checkpoint)

    def sign(self, checkpoint):
        signature = self.private_key.sign(canonical_checkpoint_payload(checkpoint))
        return {
            "record_version": "audit-chain-checkpoint-signature/v1",
            "key_id": "synthetic-ed25519-01",
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }

    def verify(self, checkpoint=None, envelope=None, store=None, at_utc="2026-11-10T10:04:00Z"):
        return verify_signed_checkpoint(
            self.events, checkpoint or self.checkpoint,
            envelope or self.envelope, store or self.store, at_utc=at_utc,
        )

    def test_valid_signature_and_checkpoint_binding(self):
        result = self.verify()
        self.assertEqual(result["signed_checkpoint_verification"], "MATCH")
        self.assertEqual(result["signature_verification"], "VALID")
        self.assertEqual(result["authority_authentication"], "NOT_ESTABLISHED")
        self.assertEqual(result["timestamp_authentication"], "NOT_ESTABLISHED")

    def test_tampered_checkpoint_invalidates_signature(self):
        changed = dict(self.checkpoint)
        changed["anchor_reference"] = "synthetic://anchor/tampered"
        result = self.verify(checkpoint=changed)
        self.assertEqual(result["signature_verification"], "INVALID")
        self.assertEqual(result["signed_checkpoint_verification"], "MISMATCH")

    def test_unknown_key_does_not_attempt_signature(self):
        envelope = dict(self.envelope)
        envelope["key_id"] = "unknown"
        result = self.verify(envelope=envelope)
        self.assertEqual(result["signed_checkpoint_verification"], "NOT_ELIGIBLE")
        self.assertEqual(result["signature_verification"], "NOT_PERFORMED")

    def test_expired_key_does_not_attempt_signature(self):
        result = self.verify(at_utc="2027-01-01T00:00:00Z")
        self.assertEqual(result["signed_checkpoint_verification"], "NOT_ELIGIBLE")
        self.assertEqual(result["key_eligibility"], "OUTSIDE_KEY_VALIDITY")

    def test_revoked_key_does_not_attempt_signature(self):
        store = {"record_version": self.store["record_version"],
                 "keys": [dict(self.store["keys"][0], status="REVOKED")]}
        result = self.verify(store=store)
        self.assertEqual(result["signed_checkpoint_verification"], "NOT_ELIGIBLE")
        self.assertEqual(result["key_eligibility"], "KEY_NOT_ACTIVE")

    def test_wrong_registration_binding_fails_even_with_valid_signature(self):
        altered_events = chain("other-registration")
        # Re-signing the checkpoint cannot make its registration identity match.
        result = verify_signed_checkpoint(
            altered_events, self.checkpoint, self.envelope, self.store,
            at_utc="2026-11-10T10:04:00Z",
        )
        self.assertEqual(result["signature_verification"], "VALID")
        self.assertEqual(result["signed_checkpoint_verification"], "MISMATCH")

    def test_invalid_signature_length_rejected(self):
        envelope = dict(self.envelope, signature_base64=base64.b64encode(b"short").decode("ascii"))
        with self.assertRaisesRegex(ValueError, "64 bytes"):
            self.verify(envelope=envelope)

    def test_unknown_envelope_field_rejected(self):
        envelope = dict(self.envelope, is_verified=True)
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            self.verify(envelope=envelope)

    def test_cli_accepts_valid_signed_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (
                ("events.json", self.events),
                ("checkpoint.json", self.checkpoint),
                ("signature.json", self.envelope),
                ("trust.json", self.store),
            ):
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = audit_chain_main([
                    str(root / "events.json"),
                    "--signed-checkpoint", str(root / "checkpoint.json"),
                    "--signature", str(root / "signature.json"),
                    "--trust-store", str(root / "trust.json"),
                    "--at-utc", "2026-11-10T10:04:00Z",
                ])
            self.assertEqual(code, 0)
            self.assertIn('"signed_checkpoint_verification": "MATCH"', output.getvalue())

    def test_cli_returns_one_for_invalid_signature(self):
        invalid = dict(self.envelope)
        signature = bytearray(base64.b64decode(invalid["signature_base64"]))
        signature[0] ^= 1
        invalid["signature_base64"] = base64.b64encode(signature).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (
                ("events.json", self.events),
                ("checkpoint.json", self.checkpoint),
                ("signature.json", invalid),
                ("trust.json", self.store),
            ):
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = audit_chain_main([
                    str(root / "events.json"),
                    "--signed-checkpoint", str(root / "checkpoint.json"),
                    "--signature", str(root / "signature.json"),
                    "--trust-store", str(root / "trust.json"),
                    "--at-utc", "2026-11-10T10:04:00Z",
                ])
            self.assertEqual(code, 1)

    def test_cli_requires_all_signed_checkpoint_inputs(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                audit_chain_main(["events.json", "--signed-checkpoint", "checkpoint.json"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
