"""Atomic single-file persistence for checkpoint payload/receipt pairs.

This module narrows the split-write failure window by storing the checkpoint
payload and its acceptance receipt in one envelope, replaced through a
same-directory os.replace(). It does not authenticate the receipt, protect an
independent rollback floor, or promise identical crash guarantees on every
filesystem.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tempfile

from experiments.checkpoint_recovery import (
    _canonical_checkpoint_sha256,
    _validate_receipt,
)
from experiments.audit_event_chain import _timestamp

_ENVELOPE_VERSION = "audit-checkpoint-acceptance-envelope/v1"
_ENVELOPE_FIELDS = {"record_version", "checkpoint", "acceptance_receipt"}
_CHECKPOINT_FIELDS = {
    "record_version",
    "registration_event_id",
    "checkpoint_sequence",
    "checkpoint_event_sha256",
    "anchored_at_utc",
    "anchor_reference",
}


class CheckpointEnvelopeDurabilityUncertain(OSError):
    """Replacement is visible, but parent-directory durability was not confirmed."""


def _validate_envelope_parts(checkpoint: dict, acceptance_receipt: dict) -> None:
    if not isinstance(checkpoint, dict):
        raise ValueError("checkpoint must be an object.")
    missing = _CHECKPOINT_FIELDS - set(checkpoint)
    extra = set(checkpoint) - _CHECKPOINT_FIELDS
    if missing:
        raise ValueError("checkpoint missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("checkpoint has unsupported field(s): " + ", ".join(sorted(extra)))
    if checkpoint["record_version"] != "audit-chain-checkpoint/v1":
        raise ValueError("checkpoint has an unsupported record_version.")
    for field in ("registration_event_id", "anchor_reference"):
        value = checkpoint[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"checkpoint {field} must be non-empty.")
    if not isinstance(checkpoint["checkpoint_event_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", checkpoint["checkpoint_event_sha256"]
    ):
        raise ValueError("checkpoint_event_sha256 must be a lowercase SHA-256 digest.")
    sequence = checkpoint["checkpoint_sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ValueError("checkpoint_sequence must be a non-negative integer.")
    anchored_at = _timestamp(checkpoint["anchored_at_utc"], "checkpoint.anchored_at_utc")
    _validate_receipt(acceptance_receipt)
    if acceptance_receipt["checkpoint_sequence"] != sequence:
        raise ValueError("acceptance receipt sequence does not match checkpoint.")
    if acceptance_receipt["checkpoint_sha256"] != _canonical_checkpoint_sha256(checkpoint):
        raise ValueError("acceptance receipt digest does not match checkpoint.")
    accepted_at = _timestamp(
        acceptance_receipt["accepted_at_utc"],
        "acceptance_receipt.accepted_at_utc",
    )
    if accepted_at < anchored_at:
        raise ValueError("acceptance receipt time precedes checkpoint anchor time.")


def build_checkpoint_envelope(checkpoint: dict, acceptance_receipt: dict) -> dict:
    """Validate and return one envelope containing the exact payload/receipt pair."""
    _validate_envelope_parts(checkpoint, acceptance_receipt)
    return {
        "record_version": _ENVELOPE_VERSION,
        "checkpoint": checkpoint,
        "acceptance_receipt": acceptance_receipt,
    }


def _validate_envelope(envelope: dict) -> dict:
    if not isinstance(envelope, dict):
        raise ValueError("checkpoint envelope must be an object.")
    missing = _ENVELOPE_FIELDS - set(envelope)
    extra = set(envelope) - _ENVELOPE_FIELDS
    if missing:
        raise ValueError("checkpoint envelope missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("checkpoint envelope has unsupported field(s): " + ", ".join(sorted(extra)))
    if envelope["record_version"] != _ENVELOPE_VERSION:
        raise ValueError("checkpoint envelope has an unsupported record_version.")
    _validate_envelope_parts(envelope["checkpoint"], envelope["acceptance_receipt"])
    return envelope


def load_checkpoint_envelope(path: str | os.PathLike) -> dict:
    """Read and validate one complete envelope; never synthesise missing members."""
    with open(path, "r", encoding="utf-8") as stream:
        envelope = json.load(stream)
    return _validate_envelope(envelope)


def write_checkpoint_envelope(
    path: str | os.PathLike,
    checkpoint: dict,
    acceptance_receipt: dict,
) -> dict:
    """Atomically replace one envelope file and report the durability boundary.

    The temporary file is created in the destination directory so os.replace()
    stays on one filesystem. The file is flushed and fsynced before replacement.
    On POSIX systems with O_DIRECTORY, the parent directory is fsynced after
    replacement. If that final fsync fails, the new file may already be visible;
    CheckpointEnvelopeDurabilityUncertain makes that state explicit.
    """
    envelope = build_checkpoint_envelope(checkpoint, acceptance_receipt)
    encoded = (
        json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    destination = Path(path)
    parent = destination.parent
    if not parent.is_dir():
        raise FileNotFoundError(f"checkpoint envelope directory does not exist: {parent}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(parent)
    )
    replaced = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
        replaced = True

        if hasattr(os, "O_DIRECTORY"):
            try:
                directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as exc:
                raise CheckpointEnvelopeDurabilityUncertain(
                    "checkpoint envelope replacement is visible, but parent-directory "
                    "fsync failed; crash durability is uncertain"
                ) from exc
            directory_status = "CONFIRMED"
        else:
            directory_status = "UNAVAILABLE"

        return {
            "replacement": "ATOMIC_SAME_DIRECTORY_REPLACE",
            "file_fsync": "CONFIRMED",
            "directory_fsync": directory_status,
            "storage_atomicity": "SINGLE_ENVELOPE_ONLY",
            "rollback_floor_protection": "NOT_PROVIDED",
        }
    finally:
        if not replaced:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
