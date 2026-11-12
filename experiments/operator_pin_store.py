"""Authenticated append-only operator pins for checkpoint witness recovery.

The caller supplies the HMAC key from an independently managed secret store.
This ledger authenticates entries and serialises cooperating local writers; it
does not prevent replay of an older, correctly authenticated ledger backup.
Rollback resistance still requires an independently retained minimum revision
and both coordinate floors, or a genuinely independent monotonic service.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import hashlib
import hmac
try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platform
    fcntl = None
import json
import os
from pathlib import Path
import re

from experiments.audit_event_chain import _timestamp

_VERSION = "audit-operator-pin-entry/v1"
_GENESIS = "0" * 64
_FIELDS = {
    "record_version", "pin_revision", "minimum_witness_sequence",
    "minimum_checkpoint_sequence", "recorded_at_utc", "previous_entry_sha256",
}


class OperatorPinDurabilityUncertain(OSError):
    """An operator-pin append may be visible, but durability is unconfirmed."""


def _key_bytes(key: object) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("operator pin HMAC key must be at least 32 bytes.")
    return key


def _integer(value: object, field: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{field} must be a {qualifier} integer.")
    return value


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _entry_mac(entry: dict, key: bytes) -> str:
    unsigned = {name: value for name, value in entry.items()
                if name != "entry_hmac_sha256"}
    return hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()


def _entry_digest(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


def _validate_entry(entry: object, *, key: bytes, revision: int,
                    previous_digest: str, previous_time: datetime | None,
                    previous_witness: int | None,
                    previous_checkpoint: int | None) -> dict:
    if not isinstance(entry, dict):
        raise ValueError("operator pin entry must be an object.")
    missing = _FIELDS - set(entry)
    extra = set(entry) - (_FIELDS | {"entry_hmac_sha256"})
    if missing:
        raise ValueError("operator pin entry missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("operator pin entry has unsupported field(s): " + ", ".join(sorted(extra)))
    if entry["record_version"] != _VERSION:
        raise ValueError("operator pin entry has an unsupported record_version.")
    if (isinstance(entry["pin_revision"], bool)
            or not isinstance(entry["pin_revision"], int)
            or entry["pin_revision"] != revision):
        raise ValueError("operator pin revision is not contiguous.")
    witness = _integer(entry["minimum_witness_sequence"], "minimum_witness_sequence", positive=True)
    checkpoint = _integer(entry["minimum_checkpoint_sequence"], "minimum_checkpoint_sequence")
    if previous_witness is not None and witness < previous_witness:
        raise ValueError("operator witness-sequence pin regression detected.")
    if previous_checkpoint is not None and checkpoint < previous_checkpoint:
        raise ValueError("operator checkpoint-floor pin regression detected.")
    previous = entry["previous_entry_sha256"]
    if not isinstance(previous, str) or not re.fullmatch(r"[0-9a-f]{64}", previous):
        raise ValueError("previous_entry_sha256 must be a lowercase SHA-256 digest.")
    if previous != previous_digest:
        raise ValueError("operator pin previous-entry digest mismatch.")
    recorded = _timestamp(entry["recorded_at_utc"], "operator_pin.recorded_at_utc")
    if previous_time is not None and recorded < previous_time:
        raise ValueError("operator pin timestamp regressed.")
    mac = entry.get("entry_hmac_sha256")
    if not isinstance(mac, str) or not re.fullmatch(r"[0-9a-f]{64}", mac):
        raise ValueError("entry_hmac_sha256 must be a lowercase SHA-256 digest.")
    if not hmac.compare_digest(mac, _entry_mac(entry, key)):
        raise ValueError("operator pin HMAC authentication failed.")
    return entry


def _load_unlocked(path: Path, key: bytes) -> list[dict]:
    entries = []
    previous_digest = _GENESIS
    previous_time = None
    previous_witness = None
    previous_checkpoint = None
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.endswith("\n"):
                raise ValueError(f"operator pin line {line_number} is incomplete.")
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"operator pin line {line_number} is invalid JSON.") from exc
            _validate_entry(
                entry, key=key, revision=len(entries),
                previous_digest=previous_digest, previous_time=previous_time,
                previous_witness=previous_witness,
                previous_checkpoint=previous_checkpoint,
            )
            entries.append(entry)
            previous_digest = _entry_digest(entry)
            previous_time = _timestamp(entry["recorded_at_utc"], "operator_pin.recorded_at_utc")
            previous_witness = entry["minimum_witness_sequence"]
            previous_checkpoint = entry["minimum_checkpoint_sequence"]
    if not entries:
        raise ValueError("operator pin ledger exists but contains no complete entries.")
    return entries


@contextmanager
def _lock(path: Path, *, exclusive: bool):
    if fcntl is None:
        raise RuntimeError("POSIX advisory locking is unavailable; refusing operator pin access.")
    lock_path = path.with_name(path.name + ".lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def load_operator_pins(
    path: str | os.PathLike, key: bytes, *,
    minimum_revision: int | None = None,
    minimum_witness_sequence: int | None = None,
    minimum_checkpoint_sequence: int | None = None,
) -> list[dict]:
    """Load authenticated pins; optional independent minima detect stale backups.

    The optional minima must come from a separately protected source. Values
    read from this same ledger do not provide independent rollback protection.
    """
    secret = _key_bytes(key)
    destination = Path(path)
    with _lock(destination, exclusive=False):
        entries = _load_unlocked(destination, secret)
    latest = entries[-1]
    for field, supplied, actual in (
        ("minimum_revision", minimum_revision, latest["pin_revision"]),
        ("minimum_witness_sequence", minimum_witness_sequence, latest["minimum_witness_sequence"]),
        ("minimum_checkpoint_sequence", minimum_checkpoint_sequence, latest["minimum_checkpoint_sequence"]),
    ):
        if supplied is not None:
            floor = _integer(supplied, field, positive=(field == "minimum_witness_sequence"))
            if actual < floor:
                raise ValueError(f"operator pin ledger is below independently retained {field}.")
    return entries


def append_operator_pins(
    path: str | os.PathLike, key: bytes, *,
    minimum_witness_sequence: int,
    minimum_checkpoint_sequence: int,
    recorded_at_utc: str,
) -> dict:
    """Append two non-decreasing operator coordinates under an exclusive lock."""
    secret = _key_bytes(key)
    witness = _integer(minimum_witness_sequence, "minimum_witness_sequence", positive=True)
    checkpoint = _integer(minimum_checkpoint_sequence, "minimum_checkpoint_sequence")
    recorded = _timestamp(recorded_at_utc, "recorded_at_utc")
    destination = Path(path)
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"operator pin directory does not exist: {destination.parent}")
    with _lock(destination, exclusive=True):
        if destination.exists():
            entries = _load_unlocked(destination, secret)
            previous = entries[-1]
            old_witness = previous["minimum_witness_sequence"]
            old_checkpoint = previous["minimum_checkpoint_sequence"]
            old_time = _timestamp(previous["recorded_at_utc"], "operator_pin.recorded_at_utc")
            if witness < old_witness:
                raise ValueError("operator witness-sequence pin regression refused.")
            if checkpoint < old_checkpoint:
                raise ValueError("operator checkpoint-floor pin regression refused.")
            if recorded < old_time:
                raise ValueError("operator pin timestamp regression refused.")
            if witness == old_witness and checkpoint == old_checkpoint:
                try:
                    descriptor = os.open(destination, os.O_RDONLY)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                        directory_status = _fsync_directory(destination.parent)
                except OSError as exc:
                    raise OperatorPinDurabilityUncertain(
                        "existing operator pins are visible, but retry fsync failed."
                    ) from exc
                return {
                    "append": "NOT_REQUIRED_IDENTICAL_PINS",
                    "pin_revision": previous["pin_revision"],
                    "minimum_witness_sequence": witness,
                    "minimum_checkpoint_sequence": checkpoint,
                    "authentication": "HMAC_SHA256_VERIFIED",
                    "directory_fsync": directory_status,
                }
            revision = previous["pin_revision"] + 1
            previous_digest = _entry_digest(previous)
        else:
            revision = 0
            previous_digest = _GENESIS

        entry = {
            "record_version": _VERSION,
            "pin_revision": revision,
            "minimum_witness_sequence": witness,
            "minimum_checkpoint_sequence": checkpoint,
            "recorded_at_utc": recorded_at_utc,
            "previous_entry_sha256": previous_digest,
        }
        entry["entry_hmac_sha256"] = _entry_mac(entry, secret)
        encoded = (_canonical(entry).decode("utf-8") + "\n").encode("utf-8")
        descriptor = os.open(
            destination, os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        try:
            try:
                written = os.write(descriptor, encoded)
                if written != len(encoded):
                    raise OSError("short operator pin append.")
                os.fsync(descriptor)
            except OSError as exc:
                raise OperatorPinDurabilityUncertain(
                    "operator pin append may be visible or incomplete; recovery must fail closed."
                ) from exc
        finally:
            os.close(descriptor)
        try:
            directory_status = _fsync_directory(destination.parent)
        except OSError as exc:
            raise OperatorPinDurabilityUncertain(
                "operator pin entry may be visible, but parent-directory fsync failed."
            ) from exc
        return {
            "append": "APPENDED",
            "pin_revision": revision,
            "minimum_witness_sequence": witness,
            "minimum_checkpoint_sequence": checkpoint,
            "entry_sha256": _entry_digest(entry),
            "authentication": "HMAC_SHA256_TAG_WRITTEN",
            "directory_fsync": directory_status,
        }


def _fsync_directory(parent: Path) -> str:
    if not hasattr(os, "O_DIRECTORY"):
        return "UNAVAILABLE"
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return "CONFIRMED"

def verify_checkpoint_floor_witness_with_operator_pins(
    receipt: dict,
    signature_envelope: dict,
    trust_store: dict,
    pin_ledger_path: str | os.PathLike,
    pin_hmac_key: bytes,
    *,
    at_utc: str,
    expected_witness_id: str,
    expected_provider_id: str,
    expected_failure_domain_id: str,
    local_storage_domain_id: str,
    minimum_pin_revision: int | None = None,
    independent_minimum_witness_sequence: int | None = None,
    independent_minimum_checkpoint_sequence: int | None = None,
    trust_store_pin: dict | None = None,
) -> dict:
    """Verify a witness receipt using authenticated retained operator pins.

    Optional independent minima must come from a separately protected recovery
    source. If all three are supplied, the loader checks the retained revision
    and both coordinates against that source before the receipt is verified.
    """
    entries = load_operator_pins(
        pin_ledger_path,
        pin_hmac_key,
        minimum_revision=minimum_pin_revision,
        minimum_witness_sequence=independent_minimum_witness_sequence,
        minimum_checkpoint_sequence=independent_minimum_checkpoint_sequence,
    )
    latest = entries[-1]
    from experiments.checkpoint_floor_witness import (
        verify_checkpoint_floor_witness_receipt,
    )

    result = verify_checkpoint_floor_witness_receipt(
        receipt,
        signature_envelope,
        trust_store,
        at_utc=at_utc,
        expected_witness_id=expected_witness_id,
        expected_provider_id=expected_provider_id,
        expected_failure_domain_id=expected_failure_domain_id,
        local_storage_domain_id=local_storage_domain_id,
        minimum_witness_sequence=latest["minimum_witness_sequence"],
        minimum_checkpoint_sequence=latest["minimum_checkpoint_sequence"],
        trust_store_pin=trust_store_pin,
    )
    result = dict(result)
    result["operator_pin_revision"] = latest["pin_revision"]
    result["operator_pin_entry_sha256"] = _entry_digest(latest)
    result["operator_pin_authentication"] = "HMAC_SHA256_VERIFIED"
    independent_checks = (
        minimum_pin_revision is not None
        and independent_minimum_witness_sequence is not None
        and independent_minimum_checkpoint_sequence is not None
    )
    result["operator_pin_rollback_guard"] = (
        "INDEPENDENT_MINIMA_SUPPLIED_AND_CHECKED"
        if independent_checks
        else "INDEPENDENT_MINIMA_NOT_ALL_SUPPLIED"
    )
    return result

def classify_checkpoint_recovery_with_operator_pins(
    events: list,
    checkpoint: dict | None,
    acceptance_receipt: dict | None,
    witness_receipt: dict,
    witness_signature_envelope: dict,
    trust_store: dict,
    floor_ledger_path: str | os.PathLike,
    operator_pin_ledger_path: str | os.PathLike,
    operator_pin_hmac_key: bytes,
    *,
    at_utc: str,
    expected_witness_id: str,
    expected_provider_id: str,
    expected_failure_domain_id: str,
    local_storage_domain_id: str,
    minimum_pin_revision: int | None = None,
    independent_minimum_witness_sequence: int | None = None,
    independent_minimum_checkpoint_sequence: int | None = None,
    trust_store_pin: dict | None = None,
) -> dict:
    """Gate recovery on authenticated operator pins and independent minima.

    All three independent minima are mandatory here: without a separately
    retained revision and both coordinates, a valid stale backup is not
    distinguishable from current state. The verifier-only helper remains
    available for diagnostic use without this recovery authorization.
    """
    if (minimum_pin_revision is None
            or independent_minimum_witness_sequence is None
            or independent_minimum_checkpoint_sequence is None):
        raise ValueError(
            "recovery requires independently retained pin revision and both coordinate minima."
        )
    entries = load_operator_pins(
        operator_pin_ledger_path,
        operator_pin_hmac_key,
        minimum_revision=minimum_pin_revision,
        minimum_witness_sequence=independent_minimum_witness_sequence,
        minimum_checkpoint_sequence=independent_minimum_checkpoint_sequence,
    )
    latest = entries[-1]
    from experiments.checkpoint_floor_witness import (
        classify_checkpoint_recovery_with_witness,
    )

    result = classify_checkpoint_recovery_with_witness(
        events,
        checkpoint,
        acceptance_receipt,
        witness_receipt,
        witness_signature_envelope,
        trust_store,
        floor_ledger_path,
        at_utc=at_utc,
        expected_witness_id=expected_witness_id,
        expected_provider_id=expected_provider_id,
        expected_failure_domain_id=expected_failure_domain_id,
        local_storage_domain_id=local_storage_domain_id,
        minimum_witness_sequence=latest["minimum_witness_sequence"],
        operator_minimum_checkpoint_sequence=latest["minimum_checkpoint_sequence"],
        trust_store_pin=trust_store_pin,
    )
    result = dict(result)
    result["operator_pin_revision"] = latest["pin_revision"]
    result["operator_pin_entry_sha256"] = _entry_digest(latest)
    result["operator_pin_authentication"] = "HMAC_SHA256_VERIFIED"
    independent_checks = (
        minimum_pin_revision is not None
        and independent_minimum_witness_sequence is not None
        and independent_minimum_checkpoint_sequence is not None
    )
    result["operator_pin_rollback_guard"] = (
        "INDEPENDENT_MINIMA_SUPPLIED_AND_CHECKED"
        if independent_checks
        else "INDEPENDENT_MINIMA_NOT_ALL_SUPPLIED"
    )
    return result
