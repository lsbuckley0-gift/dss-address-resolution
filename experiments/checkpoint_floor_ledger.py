"""Append-only local rollback-floor ledger for checkpoint recovery.

The ledger is a separate file from the checkpoint envelope. It detects a
checkpoint sequence below the latest retained floor when this ledger remains
available and intact. It is not authenticated, replicated, or protected from
loss or rollback of the ledger file itself. Writers must be externally
serialized; this module does not provide inter-process locking.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re

from experiments.audit_event_chain import _timestamp

_LEDGER_VERSION = "audit-checkpoint-floor-ledger-entry/v1"
_GENESIS_DIGEST = "0" * 64
_ENTRY_FIELDS = {
    "record_version",
    "floor_revision",
    "minimum_checkpoint_sequence",
    "recorded_at_utc",
    "previous_entry_sha256",
}


class CheckpointFloorDurabilityUncertain(OSError):
    """A floor entry may be visible, but fsync did not confirm durability."""


def _fsync_parent_directory(parent: Path) -> str:
    """Fsync the directory entry where the platform exposes O_DIRECTORY."""
    if not hasattr(os, "O_DIRECTORY"):
        return "UNAVAILABLE"
    try:
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise CheckpointFloorDurabilityUncertain(
            "floor ledger file may be visible, but parent-directory fsync failed; "
            "directory-entry durability is uncertain"
        ) from exc
    return "CONFIRMED"


def _canonical_entry_sha256(entry: dict) -> str:
    canonical = json.dumps(
        entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_entry(entry: dict, *, expected_revision: int, previous_digest: str,
                    previous_time: datetime | None, previous_floor: int | None) -> dict:
    if not isinstance(entry, dict):
        raise ValueError("floor ledger entry must be an object.")
    missing = _ENTRY_FIELDS - set(entry)
    extra = set(entry) - (_ENTRY_FIELDS | {"entry_sha256"})
    if missing:
        raise ValueError("floor ledger entry missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("floor ledger entry has unsupported field(s): " + ", ".join(sorted(extra)))
    if entry["record_version"] != _LEDGER_VERSION:
        raise ValueError("floor ledger entry has an unsupported record_version.")
    revision = entry["floor_revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision != expected_revision:
        raise ValueError("floor ledger revision is not contiguous.")
    floor = entry["minimum_checkpoint_sequence"]
    if isinstance(floor, bool) or not isinstance(floor, int) or floor < 0:
        raise ValueError("minimum_checkpoint_sequence must be a non-negative integer.")
    if previous_floor is not None and floor < previous_floor:
        raise ValueError("checkpoint rollback floor regression detected.")
    if entry["previous_entry_sha256"] != previous_digest:
        raise ValueError("floor ledger previous-entry digest mismatch.")
    if not isinstance(entry["previous_entry_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", entry["previous_entry_sha256"]
    ):
        raise ValueError("previous_entry_sha256 must be a lowercase SHA-256 digest.")
    recorded_at = _timestamp(entry["recorded_at_utc"], "floor_ledger.recorded_at_utc")
    if previous_time is not None and recorded_at < previous_time:
        raise ValueError("floor ledger timestamp regressed.")
    digest = entry.get("entry_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("entry_sha256 must be a lowercase SHA-256 digest.")
    if digest != _canonical_entry_sha256({key: value for key, value in entry.items()
                                          if key != "entry_sha256"}):
        raise ValueError("floor ledger entry digest mismatch.")
    return entry


def load_checkpoint_floor_ledger(path: str | os.PathLike) -> list[dict]:
    """Load the complete ledger; malformed or discontinuous history fails closed."""
    entries = []
    previous_digest = _GENESIS_DIGEST
    previous_time = None
    previous_floor = None
    with open(path, "r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.endswith("\n"):
                raise ValueError(f"floor ledger line {line_number} is incomplete.")
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"floor ledger line {line_number} is invalid JSON.") from exc
            _validate_entry(
                entry,
                expected_revision=len(entries),
                previous_digest=previous_digest,
                previous_time=previous_time,
                previous_floor=previous_floor,
            )
            entries.append(entry)
            previous_digest = entry["entry_sha256"]
            previous_time = _timestamp(entry["recorded_at_utc"], "floor_ledger.recorded_at_utc")
            previous_floor = entry["minimum_checkpoint_sequence"]
    if not entries:
        raise ValueError("floor ledger exists but contains no complete entries.")
    return entries


def append_checkpoint_floor(
    path: str | os.PathLike,
    minimum_checkpoint_sequence: int,
    recorded_at_utc: str,
) -> dict:
    """Append a monotonic floor entry; caller must serialize concurrent writers."""
    if (
        isinstance(minimum_checkpoint_sequence, bool)
        or not isinstance(minimum_checkpoint_sequence, int)
        or minimum_checkpoint_sequence < 0
    ):
        raise ValueError("minimum_checkpoint_sequence must be a non-negative integer.")
    recorded_at = _timestamp(recorded_at_utc, "recorded_at_utc")
    destination = Path(path)
    if destination.exists():
        entries = load_checkpoint_floor_ledger(destination)
        previous = entries[-1]
        previous_floor = previous["minimum_checkpoint_sequence"]
        previous_time = _timestamp(previous["recorded_at_utc"], "floor_ledger.recorded_at_utc")
        if minimum_checkpoint_sequence < previous_floor:
            raise ValueError("checkpoint rollback floor regression refused.")
        if recorded_at < previous_time:
            raise ValueError("floor ledger timestamp regression refused.")
        if minimum_checkpoint_sequence == previous_floor:
            try:
                descriptor = os.open(destination, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                directory_status = _fsync_parent_directory(destination.parent)
            except OSError as exc:
                raise CheckpointFloorDurabilityUncertain(
                    "existing floor ledger is visible, but retry fsync failed; "
                    "durability is uncertain"
                ) from exc
            return {
                "append": "NOT_REQUIRED_IDENTICAL_FLOOR",
                "floor_revision": previous["floor_revision"],
                "minimum_checkpoint_sequence": previous_floor,
                "file_fsync": "CONFIRMED",
                "directory_fsync": directory_status,
            }
        revision = previous["floor_revision"] + 1
        previous_digest = previous["entry_sha256"]
    else:
        revision = 0
        previous_digest = _GENESIS_DIGEST

    entry = {
        "record_version": _LEDGER_VERSION,
        "floor_revision": revision,
        "minimum_checkpoint_sequence": minimum_checkpoint_sequence,
        "recorded_at_utc": recorded_at_utc,
        "previous_entry_sha256": previous_digest,
    }
    entry["entry_sha256"] = _canonical_entry_sha256(entry)
    encoded = (
        json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")

    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        try:
            written = os.write(descriptor, encoded)
        except OSError as exc:
            raise CheckpointFloorDurabilityUncertain(
                "floor ledger append failed; the tail may be incomplete and recovery must fail closed"
            ) from exc
        if written != len(encoded):
            raise CheckpointFloorDurabilityUncertain(
                "floor ledger append was partial; ledger tail is incomplete and recovery must fail closed"
            )
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise CheckpointFloorDurabilityUncertain(
                "floor ledger entry may be visible, but fsync failed; durability is uncertain"
            ) from exc
        directory_status = _fsync_parent_directory(destination.parent)
    finally:
        os.close(descriptor)

    return {
        "append": "APPENDED",
        "floor_revision": revision,
        "minimum_checkpoint_sequence": minimum_checkpoint_sequence,
        "entry_sha256": entry["entry_sha256"],
        "file_fsync": "CONFIRMED",
        "directory_fsync": directory_status,
    }


def checkpoint_floor_value(path: str | os.PathLike) -> int:
    """Return the latest retained floor; missing/corrupt ledgers never imply zero."""
    return load_checkpoint_floor_ledger(path)[-1]["minimum_checkpoint_sequence"]
