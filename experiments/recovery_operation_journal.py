"""Durable, hash-chained journal for resumable recovery operations.

The journal records workflow progress; it is not an anti-rollback trust anchor.
Its file and lock must be protected independently from the recovery inputs.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_VERSION = "dss-recovery-operation-journal/v1"
_ZERO = "0" * 64
_HEX = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FIELDS = {"record_version", "event_sequence", "operation_id", "attestation_id",
           "attestation_sequence", "request_sha256", "state", "result_sha256",
           "previous_entry_sha256", "entry_sha256"}


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: dict) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate keys instead of silently accepting the last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str):
    """Reject JavaScript-style NaN and Infinity tokens accepted by json.loads."""
    raise ValueError(f"non-standard JSON constant is not permitted: {value}")


def _positive(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{field} must be a positive integer.")
    return value


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{field} must be a valid non-empty identifier.")
    return value


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest.")
    return value


def _entry_payload(entry: dict) -> dict:
    return {key: entry[key] for key in _FIELDS if key != "entry_sha256"}


def _validate_history(entries: list[dict]) -> None:
    operations: dict[str, dict] = {}
    attestation_owners: dict[tuple[str, int], tuple[str, str]] = {}
    for entry in entries:
        op = entry["operation_id"]
        attestation_key = (entry["attestation_id"], entry["attestation_sequence"])
        owner = (op, entry["request_sha256"])
        prior_owner = attestation_owners.get(attestation_key)
        if prior_owner is not None and prior_owner != owner:
            raise ValueError(
                "attestation sequence was reused by a different recovery operation."
            )
        attestation_owners[attestation_key] = owner
        prior = operations.get(op)
        binding = (entry["attestation_id"], entry["attestation_sequence"],
                   entry["request_sha256"])
        if prior is None:
            if entry["state"] != "RESERVED":
                raise ValueError("recovery operation must begin in RESERVED state.")
            operations[op] = {"binding": binding, "state": "RESERVED", "result": None}
            continue
        if prior["binding"] != binding:
            raise ValueError("recovery operation identifier was reused with different inputs.")
        old, new = prior["state"], entry["state"]
        if old == "RESERVED" and new == "RUNNING":
            pass
        elif old == "RUNNING" and new == "COMPLETED":
            pass
        elif old == "COMPLETED" and new == "COMPLETED" and prior["result"] == entry["result_sha256"]:
            pass
        else:
            raise ValueError(f"invalid recovery operation transition: {old} -> {new}.")
        prior["state"], prior["result"] = new, entry["result_sha256"]


def _read_unlocked(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries, previous = [], _ZERO
    for index, raw in enumerate(path.read_bytes().splitlines(keepends=True), 1):
        if not raw.endswith(b"\\n"):
            raise ValueError(f"recovery journal entry {index} is incomplete (missing newline terminator).")
        if raw == b"\\n":
            raise ValueError(f"recovery journal contains an empty line at {index}.")
        try:
            entry = json.loads(
                raw,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"recovery journal entry {index} is malformed: {exc}") from exc
        if not isinstance(entry, dict) or set(entry) != _FIELDS:
            raise ValueError(f"recovery journal entry {index} has an invalid schema.")
        if entry["record_version"] != _VERSION:
            raise ValueError(f"recovery journal entry {index} has an unsupported version.")
        if (isinstance(entry["event_sequence"], bool)
                or not isinstance(entry["event_sequence"], int)
                or entry["event_sequence"] != index):
            raise ValueError(f"recovery journal entry {index} has an invalid or non-contiguous sequence.")
        if entry["previous_entry_sha256"] != previous:
            raise ValueError(f"recovery journal entry {index} breaks the hash chain.")
        claimed = _hash(entry["entry_sha256"], "entry_sha256")
        if _digest(_entry_payload(entry)) != claimed:
            raise ValueError(f"recovery journal entry {index} digest mismatch.")
        _identifier(entry["operation_id"], "operation_id")
        _identifier(entry["attestation_id"], "attestation_id")
        _positive(entry["attestation_sequence"], "attestation_sequence")
        _hash(entry["request_sha256"], "request_sha256")
        if entry["state"] not in {"RESERVED", "RUNNING", "COMPLETED"}:
            raise ValueError(f"recovery journal entry {index} has an invalid state.")
        result = entry["result_sha256"]
        if result is not None:
            _hash(result, "result_sha256")
        if (entry["state"] == "COMPLETED") != (result is not None):
            raise ValueError(f"recovery journal entry {index} has inconsistent completion data.")
        entries.append(entry)
        previous = claimed
    _validate_history(entries)
    return entries


@contextmanager
def _exclusive(path: Path):
    if not hasattr(fcntl, "flock"):
        raise RuntimeError("POSIX advisory locking unavailable; refusing journal access.")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path.with_name(path.name + ".lock"), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _append_unlocked(path: Path, entries: list[dict], *, operation_id: str,
                     attestation_id: str, attestation_sequence: int,
                     request_sha256: str, state: str,
                     result_sha256: str | None = None) -> dict:
    payload = {
        "record_version": _VERSION, "event_sequence": len(entries) + 1,
        "operation_id": operation_id, "attestation_id": attestation_id,
        "attestation_sequence": attestation_sequence, "request_sha256": request_sha256,
        "state": state, "result_sha256": result_sha256,
        "previous_entry_sha256": entries[-1]["entry_sha256"] if entries else _ZERO,
    }
    entry = {**payload, "entry_sha256": _digest(payload)}
    encoded, existed = _canonical(entry) + b"\n", path.exists()
    descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        if os.write(descriptor, encoded) != len(encoded):
            raise OSError("short write while appending recovery journal.")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not existed:
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return entry


def begin_or_resume_recovery(journal_path: str | os.PathLike[str], *,
                             operation_id: str, attestation_id: str,
                             attestation_sequence: int, request_sha256: str) -> dict:
    """Create or resume an operation without silently rebinding its identity."""
    path = Path(journal_path)
    op, att = _identifier(operation_id, "operation_id"), _identifier(attestation_id, "attestation_id")
    seq, request = _positive(attestation_sequence, "attestation_sequence"), _hash(request_sha256, "request_sha256")
    binding = (att, seq, request)
    with _exclusive(path):
        entries = _read_unlocked(path)
        if any(
            e["attestation_id"] == att
            and e["attestation_sequence"] == seq
            and e["operation_id"] != op
            for e in entries
        ):
            raise ValueError(
                "attestation sequence is already bound to a different recovery operation."
            )
        latest = next((e for e in reversed(entries) if e["operation_id"] == op), None)
        if latest is not None:
            if (latest["attestation_id"], latest["attestation_sequence"], latest["request_sha256"]) != binding:
                raise ValueError("recovery operation identifier was reused with different inputs.")
            if latest["state"] == "COMPLETED":
                return {"operation_status": "COMPLETED", "entry": latest, "resumed": True}
            if latest["state"] == "RUNNING":
                return {"operation_status": "RESUME_REQUIRED", "entry": latest, "resumed": True}
        else:
            _append_unlocked(path, entries, operation_id=op, attestation_id=att,
                             attestation_sequence=seq, request_sha256=request, state="RESERVED")
            entries = _read_unlocked(path)
        entry = _append_unlocked(path, entries, operation_id=op, attestation_id=att,
                                 attestation_sequence=seq, request_sha256=request, state="RUNNING")
        return {"operation_status": "STARTED", "entry": entry, "resumed": False}


def complete_recovery(journal_path: str | os.PathLike[str], *,
                      operation_id: str, result_sha256: str) -> dict:
    """Durably record completion; identical completion retries are idempotent."""
    path, op = Path(journal_path), _identifier(operation_id, "operation_id")
    result = _hash(result_sha256, "result_sha256")
    with _exclusive(path):
        entries = _read_unlocked(path)
        latest = next((e for e in reversed(entries) if e["operation_id"] == op), None)
        if latest is None:
            raise ValueError("unknown recovery operation.")
        if latest["state"] == "COMPLETED":
            if latest["result_sha256"] != result:
                raise ValueError("completed recovery operation has a different result digest.")
            return {"operation_status": "COMPLETED", "entry": latest, "idempotent": True}
        if latest["state"] != "RUNNING":
            raise ValueError("recovery operation must be RUNNING before completion.")
        entry = _append_unlocked(path, entries, operation_id=op,
                                 attestation_id=latest["attestation_id"],
                                 attestation_sequence=latest["attestation_sequence"],
                                 request_sha256=latest["request_sha256"],
                                 state="COMPLETED", result_sha256=result)
        return {"operation_status": "COMPLETED", "entry": entry, "idempotent": False}


def inspect_recovery_operations(journal_path: str | os.PathLike[str]) -> dict[str, dict[str, Any]]:
    """Return latest validated state per operation; corruption fails closed."""
    path = Path(journal_path)
    with _exclusive(path):
        entries = _read_unlocked(path)
    latest = {}
    for entry in entries:
        latest[entry["operation_id"]] = entry
    return latest
