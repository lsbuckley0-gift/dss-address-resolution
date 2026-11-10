"""Tests for detached Ed25519 checkpoint signature verification."""
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.audit_event_chain import append_audit_event
from experiments.audit_event_chain import verify_checkpoint_series
from experiments.audit_event_chain import main as audit_chain_main
from experiments.trust_policy_pin import trust_store_sha256
from experiments.rfc3161_anchor_provenance import canonical_provenance_payload
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

    def provenance_inputs(self):
        anchor = b"-----BEGIN CERTIFICATE-----\\nsynthetic-root\\n-----END CERTIFICATE-----\\n"
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        governance_store = {
            "record_version": "audit-trust-store/v1",
            "keys": [{
                "key_id": "synthetic-governance",
                "authority_name": "Synthetic timestamp authority",
                "algorithm": "Ed25519",
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "purposes": ["RFC3161_TRUST_ANCHOR_PROVENANCE"],
                "valid_from_utc": "2026-01-01T00:00:00Z",
                "valid_until_utc": "2027-01-01T00:00:00Z",
                "status": "ACTIVE",
                "trust_basis_reference": "synthetic fixture only",
            }],
        }
        attestation = {
            "record_version": "rfc3161-tsa-anchor-provenance/v1",
            "attestation_id": "checkpoint-integration-test",
            "authority_name": "Synthetic timestamp authority",
            "anchor_sha256": hashlib.sha256(anchor).hexdigest(),
            "intended_usage": "RFC3161_TSA_TRUST_ANCHOR",
            "policy_version": "rfc3161-tsa-anchor-policy/v1",
            "sequence": 4,
            "issued_at_utc": "2026-11-01T00:00:00Z",
            "expires_at_utc": "2026-12-01T00:00:00Z",
            "source_reference": "synthetic://checkpoint-integration",
        }
        signature = private.sign(canonical_provenance_payload(attestation))
        envelope = {
            "record_version": "rfc3161-tsa-anchor-provenance-signature/v1",
            "key_id": "synthetic-governance",
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }
        anchor_pin = {
            "sha256": hashlib.sha256(anchor).hexdigest(),
            "source_reference": "synthetic://independent-anchor-pin",
        }
        return anchor, anchor_pin, attestation, envelope, governance_store

    def test_checkpoint_timestamp_can_opt_in_to_provenance_first_verification(self):
        timestamp = {
            "timestamp_verification": "VALID",
            "tsa_asserted_gen_time_utc": "2026-11-10T10:00:30Z",
        }
        anchor, anchor_pin, attestation, envelope, governance_store = self.provenance_inputs()
        with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp", return_value=timestamp) as verify:
            result = verify_signed_checkpoint(
                self.events, self.checkpoint, self.envelope, self.store,
                at_utc="2026-11-10T10:04:00Z",
                timestamp_token_der=b"synthetic-token",
                timestamp_trust_anchor_pem=anchor,
                timestamp_trust_anchor_pin=anchor_pin,
                timestamp_anchor_attestation=attestation,
                timestamp_anchor_signature_envelope=envelope,
                timestamp_governance_trust_store=governance_store,
                timestamp_governance_minimum_sequence=4,
                timestamp_governance_trust_store_pin={
                    "sha256": trust_store_sha256(governance_store),
                    "source_reference": "synthetic://independent-governance-pin",
                },
            )
        self.assertEqual(result["signed_checkpoint_verification"], "MATCH")
        self.assertEqual(result["registration_timestamp_binding"], "MATCH")
        self.assertEqual(
            result["timestamp_anchor_provenance"]["provenance_verification"],
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE",
        )
        self.assertEqual(result["governance_authentication"], "NOT_ESTABLISHED")
        self.assertEqual(
            result["timestamp_anchor_provenance"]["governance_trust_store_pin"]["trust_policy_pin"],
            "MATCH",
        )
        verify.assert_called_once()
        self.assertEqual(verify.call_args.args[1], canonical_checkpoint_payload(self.checkpoint))

    def test_checkpoint_provenance_failure_prevents_timestamp_verification(self):
        anchor, anchor_pin, attestation, envelope, governance_store = self.provenance_inputs()
        changed_signature = bytearray(base64.b64decode(envelope["signature_base64"]))
        changed_signature[0] ^= 1
        envelope["signature_base64"] = base64.b64encode(changed_signature).decode("ascii")
        with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp") as verify:
            result = verify_signed_checkpoint(
                self.events, self.checkpoint, self.envelope, self.store,
                at_utc="2026-11-10T10:04:00Z",
                timestamp_token_der=b"synthetic-token",
                timestamp_trust_anchor_pem=anchor,
                timestamp_trust_anchor_pin=anchor_pin,
                timestamp_anchor_attestation=attestation,
                timestamp_anchor_signature_envelope=envelope,
                timestamp_governance_trust_store=governance_store,
                timestamp_governance_minimum_sequence=4,
            )
        self.assertEqual(result["signed_checkpoint_verification"], "MISMATCH")
        self.assertEqual(result["registration_timestamp_binding"], "NOT_VERIFIED")
        self.assertEqual(
            result["timestamp_anchor_provenance"]["provenance_verification"],
            "INVALID_SIGNATURE",
        )
        self.assertEqual(result["timestamp_evidence"]["timestamp_verification"], "NOT_PERFORMED")
        verify.assert_not_called()

    def test_governance_store_pin_mismatch_prevents_timestamp_verification(self):
        anchor, anchor_pin, attestation, envelope, governance_store = self.provenance_inputs()
        with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp") as verify:
            result = verify_signed_checkpoint(
                self.events, self.checkpoint, self.envelope, self.store,
                at_utc="2026-11-10T10:04:00Z",
                timestamp_token_der=b"synthetic-token",
                timestamp_trust_anchor_pem=anchor,
                timestamp_trust_anchor_pin=anchor_pin,
                timestamp_anchor_attestation=attestation,
                timestamp_anchor_signature_envelope=envelope,
                timestamp_governance_trust_store=governance_store,
                timestamp_governance_minimum_sequence=4,
                timestamp_governance_trust_store_pin={
                    "sha256": "0" * 64,
                    "source_reference": "synthetic://wrong-governance-pin",
                },
            )
        self.assertEqual(result["signed_checkpoint_verification"], "MISMATCH")
        self.assertEqual(
            result["timestamp_anchor_provenance"]["provenance_verification"],
            "GOVERNANCE_POLICY_PIN_MISMATCH",
        )
        self.assertEqual(result["timestamp_evidence"]["timestamp_verification"], "NOT_PERFORMED")
        verify.assert_not_called()

    def test_partial_timestamp_provenance_bundle_rejected(self):
        anchor, anchor_pin, attestation, envelope, governance_store = self.provenance_inputs()
        with self.assertRaisesRegex(ValueError, "must be supplied together"):
            verify_signed_checkpoint(
                self.events, self.checkpoint, self.envelope, self.store,
                at_utc="2026-11-10T10:04:00Z",
                timestamp_token_der=b"synthetic-token",
                timestamp_trust_anchor_pem=anchor,
                timestamp_trust_anchor_pin=anchor_pin,
                timestamp_anchor_attestation=attestation,
            )

    def test_provenance_bundle_without_timestamp_evidence_rejected(self):
        _, _, attestation, envelope, governance_store = self.provenance_inputs()
        with self.assertRaisesRegex(ValueError, "complete RFC 3161 timestamp inputs"):
            verify_signed_checkpoint(
                self.events, self.checkpoint, self.envelope, self.store,
                at_utc="2026-11-10T10:04:00Z",
                timestamp_anchor_attestation=attestation,
                timestamp_anchor_signature_envelope=envelope,
                timestamp_governance_trust_store=governance_store,
                timestamp_governance_minimum_sequence=4,
            )

    def test_valid_signature_and_checkpoint_binding(self):
        result = self.verify()
        self.assertEqual(result["signed_checkpoint_verification"], "MATCH")
        self.assertEqual(result["signature_verification"], "VALID")
        self.assertEqual(result["authority_authentication"], "NOT_ESTABLISHED")
        self.assertEqual(result["timestamp_authentication"], "NOT_ESTABLISHED")

    def test_policy_pin_mismatch_blocks_signature_verification(self):
        pin = {
            "sha256": "0" * 64,
            "source_reference": "operator-provisioned://wrong-pin",
        }
        result = verify_signed_checkpoint(
            self.events, self.checkpoint, self.envelope, self.store,
            at_utc="2026-11-10T10:04:00Z", trust_store_pin=pin,
        )
        self.assertEqual(result["signed_checkpoint_verification"], "POLICY_PIN_MISMATCH")
        self.assertEqual(result["signature_verification"], "NOT_PERFORMED")

    def test_matching_policy_pin_is_reported(self):
        pin = {
            "sha256": trust_store_sha256(self.store),
            "source_reference": "operator-provisioned://test-pin",
        }
        result = verify_signed_checkpoint(
            self.events, self.checkpoint, self.envelope, self.store,
            at_utc="2026-11-10T10:04:00Z", trust_store_pin=pin,
        )
        self.assertEqual(result["signed_checkpoint_verification"], "MATCH")
        self.assertEqual(result["trust_policy_pin"]["trust_policy_pin"], "MATCH")

    def test_valid_timestamp_binds_registration_checkpoint_before_outcome_access(self):
        timestamp = {
            "timestamp_verification": "VALID",
            "tsa_asserted_gen_time_utc": "2026-11-10T10:00:30Z",
        }
        anchor = b"-----BEGIN CERTIFICATE-----\\nsynthetic-root\\n-----END CERTIFICATE-----\\n"
        pin = {"sha256": "a" * 64, "source_reference": "synthetic://tsa-root-pin"}
        with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp", return_value=timestamp) as verify:
            result = verify_signed_checkpoint(
                self.events, self.checkpoint, self.envelope, self.store,
                at_utc="2026-11-10T10:04:00Z",
                timestamp_token_der=b"synthetic-token",
                timestamp_trust_anchor_pem=anchor,
                timestamp_trust_anchor_pin=pin,
            )
        self.assertEqual(result["signed_checkpoint_verification"], "MATCH")
        self.assertEqual(result["registration_timestamp_binding"], "MATCH")
        self.assertEqual(result["timestamp_authentication"], "CRYPTOGRAPHICALLY_VALID_RELATIVE_TO_CALLER_ANCHOR")
        self.assertEqual(verify.call_args.args[1], canonical_checkpoint_payload(self.checkpoint))

    def test_timestamp_at_or_after_outcome_access_fails_registration_binding(self):
        timestamp = {
            "timestamp_verification": "VALID",
            "tsa_asserted_gen_time_utc": "2026-11-10T10:01:00Z",
        }
        anchor = b"-----BEGIN CERTIFICATE-----\\nsynthetic-root\\n-----END CERTIFICATE-----\\n"
        pin = {"sha256": "a" * 64, "source_reference": "synthetic://tsa-root-pin"}
        with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp", return_value=timestamp):
            result = verify_signed_checkpoint(
                self.events, self.checkpoint, self.envelope, self.store,
                at_utc="2026-11-10T10:04:00Z",
                timestamp_token_der=b"synthetic-token",
                timestamp_trust_anchor_pem=anchor,
                timestamp_trust_anchor_pin=pin,
            )
        self.assertEqual(result["registration_timestamp_binding"], "MISMATCH")
        self.assertEqual(result["signed_checkpoint_verification"], "MISMATCH")

    def test_invalid_timestamp_does_not_establish_registration_binding(self):
        timestamp = {"timestamp_verification": "INVALID"}
        anchor = b"-----BEGIN CERTIFICATE-----\\nsynthetic-root\\n-----END CERTIFICATE-----\\n"
        pin = {"sha256": "a" * 64, "source_reference": "synthetic://tsa-root-pin"}
        with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp", return_value=timestamp):
            result = verify_signed_checkpoint(
                self.events, self.checkpoint, self.envelope, self.store,
                at_utc="2026-11-10T10:04:00Z",
                timestamp_token_der=b"synthetic-token",
                timestamp_trust_anchor_pem=anchor,
                timestamp_trust_anchor_pin=pin,
            )
        self.assertEqual(result["registration_timestamp_binding"], "NOT_VERIFIED")
        self.assertEqual(result["signed_checkpoint_verification"], "MISMATCH")

    def test_partial_timestamp_inputs_rejected(self):
        with self.assertRaisesRegex(ValueError, "must be supplied together"):
            verify_signed_checkpoint(
                self.events, self.checkpoint, self.envelope, self.store,
                at_utc="2026-11-10T10:04:00Z",
                timestamp_token_der=b"synthetic-token",
            )

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
                ("trust-pin.json", {"sha256": trust_store_sha256(self.store), "source_reference": "operator-provisioned://cli-test"}),
            ):
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = audit_chain_main([
                    str(root / "events.json"),
                    "--signed-checkpoint", str(root / "checkpoint.json"),
                    "--signature", str(root / "signature.json"),
                    "--trust-store", str(root / "trust.json"),
                    "--trust-store-pin", str(root / "trust-pin.json"),
                    "--at-utc", "2026-11-10T10:04:00Z",
                ])
            self.assertEqual(code, 0)
            self.assertIn('"signed_checkpoint_verification": "MATCH"', output.getvalue())
            self.assertIn('"trust_policy_pin": "MATCH"', output.getvalue())

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

    def test_cli_passes_complete_timestamp_evidence_to_verifier(self):
        timestamp = {
            "timestamp_verification": "VALID",
            "tsa_asserted_gen_time_utc": "2026-11-10T10:00:30Z",
        }
        anchor = b"-----BEGIN CERTIFICATE-----\\nsynthetic-root\\n-----END CERTIFICATE-----\\n"
        pin = {"sha256": "a" * 64, "source_reference": "synthetic://tsa-root-pin"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (
                ("events.json", self.events),
                ("checkpoint.json", self.checkpoint),
                ("signature.json", self.envelope),
                ("trust.json", self.store),
                ("timestamp-pin.json", pin),
            ):
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            (root / "token.der").write_bytes(b"synthetic-token")
            (root / "anchor.pem").write_bytes(anchor)
            output = io.StringIO()
            with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp", return_value=timestamp):
                with contextlib.redirect_stdout(output):
                    code = audit_chain_main([
                        str(root / "events.json"),
                        "--signed-checkpoint", str(root / "checkpoint.json"),
                        "--signature", str(root / "signature.json"),
                        "--trust-store", str(root / "trust.json"),
                        "--at-utc", "2026-11-10T10:04:00Z",
                        "--timestamp-token", str(root / "token.der"),
                        "--timestamp-trust-anchor", str(root / "anchor.pem"),
                        "--timestamp-trust-anchor-pin", str(root / "timestamp-pin.json"),
                    ])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(report["signed_external_checkpoint"]["registration_timestamp_binding"], "MATCH")

    def test_cli_accepts_provenance_first_timestamp_bundle(self):
        timestamp = {
            "timestamp_verification": "VALID",
            "tsa_asserted_gen_time_utc": "2026-11-10T10:00:30Z",
        }
        anchor, anchor_pin, attestation, provenance_envelope, governance_store = self.provenance_inputs()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (
                ("events.json", self.events),
                ("checkpoint.json", self.checkpoint),
                ("signature.json", self.envelope),
                ("trust.json", self.store),
                ("timestamp-pin.json", anchor_pin),
                ("anchor-attestation.json", attestation),
                ("anchor-signature.json", provenance_envelope),
                ("governance-store.json", governance_store),
            ):
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            (root / "token.der").write_bytes(b"synthetic-token")
            (root / "anchor.pem").write_bytes(anchor)
            output = io.StringIO()
            with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp", return_value=timestamp):
                with contextlib.redirect_stdout(output):
                    code = audit_chain_main([
                        str(root / "events.json"),
                        "--signed-checkpoint", str(root / "checkpoint.json"),
                        "--signature", str(root / "signature.json"),
                        "--trust-store", str(root / "trust.json"),
                        "--at-utc", "2026-11-10T10:04:00Z",
                        "--timestamp-token", str(root / "token.der"),
                        "--timestamp-trust-anchor", str(root / "anchor.pem"),
                        "--timestamp-trust-anchor-pin", str(root / "timestamp-pin.json"),
                        "--timestamp-anchor-attestation", str(root / "anchor-attestation.json"),
                        "--timestamp-anchor-signature", str(root / "anchor-signature.json"),
                        "--timestamp-governance-trust-store", str(root / "governance-store.json"),
                        "--timestamp-governance-minimum-sequence", "4",
                    ])
        report = json.loads(output.getvalue())
        signed = report["signed_external_checkpoint"]
        self.assertEqual(code, 0)
        self.assertEqual(signed["registration_timestamp_binding"], "MATCH")
        self.assertEqual(
            signed["timestamp_anchor_provenance"]["provenance_verification"],
            "VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE",
        )

    def test_cli_invalid_provenance_exits_nonzero_without_timestamp_verification(self):
        anchor, anchor_pin, attestation, provenance_envelope, governance_store = self.provenance_inputs()
        damaged = bytearray(base64.b64decode(provenance_envelope["signature_base64"]))
        damaged[0] ^= 1
        provenance_envelope["signature_base64"] = base64.b64encode(damaged).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (
                ("events.json", self.events),
                ("checkpoint.json", self.checkpoint),
                ("signature.json", self.envelope),
                ("trust.json", self.store),
                ("timestamp-pin.json", anchor_pin),
                ("anchor-attestation.json", attestation),
                ("anchor-signature.json", provenance_envelope),
                ("governance-store.json", governance_store),
            ):
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            (root / "token.der").write_bytes(b"synthetic-token")
            (root / "anchor.pem").write_bytes(anchor)
            output = io.StringIO()
            with patch("experiments.rfc3161_timestamp.verify_rfc3161_timestamp") as verify:
                with contextlib.redirect_stdout(output):
                    code = audit_chain_main([
                        str(root / "events.json"),
                        "--signed-checkpoint", str(root / "checkpoint.json"),
                        "--signature", str(root / "signature.json"),
                        "--trust-store", str(root / "trust.json"),
                        "--at-utc", "2026-11-10T10:04:00Z",
                        "--timestamp-token", str(root / "token.der"),
                        "--timestamp-trust-anchor", str(root / "anchor.pem"),
                        "--timestamp-trust-anchor-pin", str(root / "timestamp-pin.json"),
                        "--timestamp-anchor-attestation", str(root / "anchor-attestation.json"),
                        "--timestamp-anchor-signature", str(root / "anchor-signature.json"),
                        "--timestamp-governance-trust-store", str(root / "governance-store.json"),
                        "--timestamp-governance-minimum-sequence", "4",
                    ])
        report = json.loads(output.getvalue())["signed_external_checkpoint"]
        self.assertEqual(code, 1)
        self.assertEqual(report["signed_checkpoint_verification"], "MISMATCH")
        self.assertEqual(report["timestamp_anchor_provenance"]["provenance_verification"], "INVALID_SIGNATURE")
        self.assertEqual(report["timestamp_evidence"]["timestamp_verification"], "NOT_PERFORMED")
        verify.assert_not_called()

    def test_cli_rejects_negative_provenance_sequence_floor(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                audit_chain_main([
                    "events.json",
                    "--timestamp-governance-minimum-sequence", "-1",
                ])
        self.assertEqual(raised.exception.code, 2)

    def test_cli_rejects_partial_timestamp_provenance_bundle(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                audit_chain_main([
                    "events.json", "--signed-checkpoint", "checkpoint.json",
                    "--signature", "signature.json", "--trust-store", "trust.json",
                    "--at-utc", "2026-11-10T10:04:00Z",
                    "--timestamp-anchor-attestation", "attestation.json",
                ])
        self.assertEqual(raised.exception.code, 2)

    def test_cli_requires_complete_timestamp_verification_inputs(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                audit_chain_main([
                    "events.json", "--signed-checkpoint", "checkpoint.json",
                    "--signature", "signature.json", "--trust-store", "trust.json",
                    "--at-utc", "2026-11-10T10:04:00Z", "--timestamp-token", "token.der",
                ])
        self.assertEqual(raised.exception.code, 2)

    def test_cli_requires_all_signed_checkpoint_inputs(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                audit_chain_main(["events.json", "--signed-checkpoint", "checkpoint.json"])
        self.assertEqual(raised.exception.code, 2)


class CheckpointSeriesContinuityTests(unittest.TestCase):
    def setUp(self):
        self.events = chain()
        self.first = checkpoint_for(self.events)
        self.second = {
            "record_version": "audit-chain-checkpoint/v1",
            "registration_event_id": "reg-1",
            "checkpoint_sequence": 2,
            "checkpoint_event_sha256": self.events[2]["event_sha256"],
            "anchored_at_utc": "2026-11-10T10:03:00Z",
            "anchor_reference": "synthetic://anchor/002",
        }

    def test_ordered_sparse_checkpoints_bind_the_same_chain(self):
        result = verify_checkpoint_series(self.events, [self.first, self.second])
        self.assertEqual(result["checkpoint_series_integrity"], "MATCH")
        self.assertEqual(
            [item["series_order"] for item in result["checkpoints"]],
            ["INCREASING", "INCREASING"],
        )

    def test_reordered_checkpoints_fail_sequence_continuity(self):
        result = verify_checkpoint_series(self.events, [self.second, self.first])
        self.assertEqual(result["checkpoint_series_integrity"], "MISMATCH")
        self.assertEqual(
            result["checkpoints"][1]["series_order"],
            "NON_INCREASING_SEQUENCE",
        )

    def test_replayed_checkpoint_fails_sequence_continuity(self):
        replay = dict(self.first)
        replay["anchored_at_utc"] = "2026-11-10T10:04:00Z"
        replay["anchor_reference"] = "synthetic://anchor/replay"
        result = verify_checkpoint_series(self.events, [self.first, replay])
        self.assertEqual(result["checkpoint_series_integrity"], "MISMATCH")
        self.assertEqual(
            result["checkpoints"][1]["series_order"],
            "NON_INCREASING_SEQUENCE",
        )

    def test_non_increasing_anchor_time_fails_series(self):
        later_sequence_earlier_time = dict(
            self.second, anchored_at_utc="2026-11-10T10:02:00Z"
        )
        result = verify_checkpoint_series(
            self.events, [self.first, later_sequence_earlier_time]
        )
        self.assertEqual(result["checkpoint_series_integrity"], "MISMATCH")
        self.assertEqual(
            result["checkpoints"][1]["series_order"],
            "NON_INCREASING_ANCHOR_TIME",
        )

    def test_duplicate_anchor_reference_fails_series(self):
        duplicate = dict(
            self.second,
            anchor_reference=self.first["anchor_reference"],
        )
        result = verify_checkpoint_series(self.events, [self.first, duplicate])
        self.assertEqual(result["checkpoint_series_integrity"], "MISMATCH")
        self.assertEqual(
            result["checkpoints"][1]["series_order"],
            "DUPLICATE_ANCHOR_REFERENCE",
        )

    def test_checkpoint_digest_mismatch_fails_even_when_order_increases(self):
        changed = dict(
            self.second,
            checkpoint_event_sha256="0" * 64,
        )
        result = verify_checkpoint_series(self.events, [self.first, changed])
        self.assertEqual(result["checkpoint_series_integrity"], "MISMATCH")
        self.assertEqual(result["checkpoints"][1]["checkpoint_binding"], "MISMATCH")

    def test_operator_retained_floor_accepts_equal_or_newer_checkpoint(self):
        result = verify_checkpoint_series(
            self.events, [self.first, self.second], minimum_sequence=2
        )
        self.assertEqual(result["checkpoint_series_integrity"], "MATCH")
        self.assertEqual(result["rollback_floor"], "MEETS_FLOOR")
        self.assertEqual(result["minimum_sequence"], 2)

    def test_operator_retained_floor_rejects_stale_checkpoint_series(self):
        result = verify_checkpoint_series(
            self.events, [self.first], minimum_sequence=1
        )
        self.assertEqual(result["checkpoint_series_integrity"], "MISMATCH")
        self.assertEqual(result["rollback_floor"], "BELOW_FLOOR")

    def test_operator_retained_floor_must_be_non_negative_integer(self):
        for invalid in (-1, True, 1.5, "2"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "non-negative integer"):
                    verify_checkpoint_series(
                        self.events, [self.first], minimum_sequence=invalid
                    )


if __name__ == "__main__":
    unittest.main()
