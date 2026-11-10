"""Fail-closed RFC 3161 timestamp-token verification.

OpenSSL verifies the token signature, message imprint, TSA certificate purpose,
and certificate path. The caller supplies and pins the trust-anchor PEM bytes.
A successful result does not authenticate the anchor's provenance or prove
that the TSA's asserted time or the underlying event is true.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

_PIN_FIELDS = {"sha256", "source_reference"}
_MAX_TOKEN_BYTES = 8 * 1024 * 1024
_MAX_CERT_BUNDLE_BYTES = 2 * 1024 * 1024
_MONTHS = {
    name: number for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
_TIME_LINE = re.compile(
    r"^Time stamp:\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+"
    r"(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+GMT\s*$",
    re.MULTILINE,
)


def trust_anchor_sha256(pem_bytes: bytes) -> str:
    """Digest the exact PEM bytes supplied as the timestamp trust anchor."""
    if not isinstance(pem_bytes, bytes) or not pem_bytes:
        raise ValueError("trust anchor must be non-empty PEM bytes.")
    return hashlib.sha256(pem_bytes).hexdigest()


def _validate_pin(anchor: bytes, pin: dict) -> dict:
    if not isinstance(pin, dict):
        raise ValueError("trust-anchor pin must be an object.")
    missing = _PIN_FIELDS - set(pin)
    extra = set(pin) - _PIN_FIELDS
    if missing:
        raise ValueError("trust-anchor pin missing field(s): " + ", ".join(sorted(missing)))
    if extra:
        raise ValueError("trust-anchor pin has unsupported field(s): " + ", ".join(sorted(extra)))
    digest = pin["sha256"]
    source = pin["source_reference"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("trust-anchor pin sha256 must be a lowercase SHA-256 digest.")
    if not isinstance(source, str) or not source.strip():
        raise ValueError("trust-anchor pin source_reference must be non-empty.")
    actual = trust_anchor_sha256(anchor)
    return {
        "trust_anchor_pin": "MATCH" if actual == digest else "MISMATCH",
        "expected_sha256": digest,
        "observed_sha256": actual,
        "source_reference": source,
        "pin_source_authentication": "NOT_INDEPENDENTLY_AUTHENTICATED",
    }


def _claimed_gen_time(token_path: Path, openssl_binary: str, timeout_seconds: int) -> datetime:
    completed = subprocess.run(
        [openssl_binary, "ts", "-reply", "-in", str(token_path), "-token_in", "-text"],
        capture_output=True, text=True, timeout=timeout_seconds, check=False,
    )
    if completed.returncode != 0:
        raise ValueError("OpenSSL could not parse the RFC 3161 timestamp token.")
    match = _TIME_LINE.search(completed.stdout + "\n" + completed.stderr)
    if match is None:
        raise ValueError("RFC 3161 token did not expose a supported GMT generation-time field.")
    month, day, hour, minute, second, year = match.groups()
    return datetime(
        int(year), _MONTHS[month], int(day), int(hour), int(minute), int(second),
        tzinfo=timezone.utc,
    )


def verify_rfc3161_timestamp(
    token_der: bytes,
    data: bytes,
    trust_anchor_pem: bytes,
    trust_anchor_pin: dict,
    *,
    intermediates_pem: bytes | None = None,
    openssl_binary: str = "openssl",
    timeout_seconds: int = 10,
) -> dict:
    """Verify a DER TimeStampToken against exact data and a pinned caller anchor.

    token_der must be a DER-encoded TimeStampToken (ContentInfo), not a
    TimeStampResp wrapper. The token's signed genTime is used as the X.509
    certificate-path validation time. Fractional-second genTime display values
    are rejected because OpenSSL's -attime interface accepts integer seconds.
    No system CA directories are consulted.
    """
    if not isinstance(token_der, bytes) or not token_der or len(token_der) > _MAX_TOKEN_BYTES:
        raise ValueError("token_der must be non-empty bytes no larger than 8 MiB.")
    if not isinstance(data, bytes):
        raise ValueError("data must be bytes.")
    if not isinstance(trust_anchor_pem, bytes) or not trust_anchor_pem:
        raise ValueError("trust_anchor_pem must be non-empty PEM bytes.")
    if len(trust_anchor_pem) > _MAX_CERT_BUNDLE_BYTES:
        raise ValueError("trust anchor PEM exceeds 2 MiB.")
    if b"-----BEGIN CERTIFICATE-----" not in trust_anchor_pem:
        raise ValueError("trust_anchor_pem must contain at least one PEM certificate.")
    if intermediates_pem is not None:
        if not isinstance(intermediates_pem, bytes) or not intermediates_pem:
            raise ValueError("intermediates_pem must be non-empty PEM bytes when supplied.")
        if len(intermediates_pem) > _MAX_CERT_BUNDLE_BYTES:
            raise ValueError("intermediates PEM exceeds 2 MiB.")
        if b"-----BEGIN CERTIFICATE-----" not in intermediates_pem:
            raise ValueError("intermediates_pem must contain PEM certificates.")
    if not isinstance(openssl_binary, str) or not openssl_binary.strip():
        raise ValueError("openssl_binary must be a non-empty executable name.")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 120:
        raise ValueError("timeout_seconds must be an integer from 1 through 120.")

    pin_result = _validate_pin(trust_anchor_pem, trust_anchor_pin)
    if pin_result["trust_anchor_pin"] != "MATCH":
        return {
            "timestamp_verification": "TRUST_ANCHOR_PIN_MISMATCH",
            "token_signature_and_path": "NOT_PERFORMED",
            "message_imprint": "NOT_PERFORMED",
            "trust_anchor": pin_result,
            "timestamp_authentication": "NOT_ESTABLISHED",
            "event_truth": "NOT_ESTABLISHED",
            "tsa_certificate_revocation": "NOT_CHECKED",
            "historical_revocation_assurance": "NOT_ESTABLISHED",
        }

    try:
        with tempfile.TemporaryDirectory(prefix="dss-rfc3161-") as directory:
            root = Path(directory)
            token_path = root / "timestamp-token.der"
            data_path = root / "imprint-data.bin"
            anchor_path = root / "trust-anchor.pem"
            token_path.write_bytes(token_der)
            data_path.write_bytes(data)
            anchor_path.write_bytes(trust_anchor_pem)
            empty_ca_path = root / "empty-ca-path"
            empty_ca_path.mkdir()
            intermediate_path = None
            if intermediates_pem is not None:
                intermediate_path = root / "intermediates.pem"
                intermediate_path.write_bytes(intermediates_pem)

            gen_time = _claimed_gen_time(token_path, openssl_binary, timeout_seconds)
            epoch = str(int(gen_time.timestamp()))
            command = [
                openssl_binary, "ts", "-verify", "-token_in",
                "-in", str(token_path), "-data", str(data_path),
                "-CAfile", str(anchor_path), "-attime", epoch,
                "-purpose", "timestampsign", "-CApath", str(empty_ca_path),
                "-x509_strict",
            ]
            if intermediate_path is not None:
                command.extend(["-untrusted", str(intermediate_path)])
            completed = subprocess.run(
                command, capture_output=True, text=True,
                timeout=timeout_seconds, check=False,
            )
    except FileNotFoundError:
        return {
            "timestamp_verification": "VERIFICATION_UNAVAILABLE",
            "token_signature_and_path": "NOT_PERFORMED",
            "message_imprint": "NOT_PERFORMED",
            "trust_anchor": pin_result,
            "error": "OpenSSL executable was not found.",
            "tsa_certificate_revocation": "NOT_CHECKED",
            "historical_revocation_assurance": "NOT_ESTABLISHED",
            "timestamp_authentication": "NOT_ESTABLISHED",
            "event_truth": "NOT_ESTABLISHED",
        }
    except subprocess.TimeoutExpired:
        return {
            "timestamp_verification": "VERIFICATION_UNAVAILABLE",
            "token_signature_and_path": "NOT_COMPLETED",
            "message_imprint": "NOT_COMPLETED",
            "trust_anchor": pin_result,
            "error": "OpenSSL timestamp verification timed out.",
            "tsa_certificate_revocation": "NOT_CHECKED",
            "historical_revocation_assurance": "NOT_ESTABLISHED",
            "timestamp_authentication": "NOT_ESTABLISHED",
            "event_truth": "NOT_ESTABLISHED",
        }
    except ValueError as exc:
        return {
            "timestamp_verification": "INVALID_TOKEN",
            "token_signature_and_path": "NOT_VERIFIED",
            "message_imprint": "NOT_VERIFIED",
            "trust_anchor": pin_result,
            "error": str(exc),
            "tsa_certificate_revocation": "NOT_CHECKED",
            "historical_revocation_assurance": "NOT_ESTABLISHED",
            "timestamp_authentication": "NOT_ESTABLISHED",
            "event_truth": "NOT_ESTABLISHED",
        }

    verified = completed.returncode == 0
    return {
        "timestamp_verification": "VALID" if verified else "INVALID",
        "token_signature_and_path": "VALID" if verified else "INVALID",
        "message_imprint": "MATCH" if verified else "NOT_ESTABLISHED",
        "tsa_asserted_gen_time_utc": gen_time.isoformat().replace("+00:00", "Z"),
        "certificate_validation_time": "TOKEN_GEN_TIME",
        "trust_anchor": pin_result,
        "anchor_provenance": "NOT_ESTABLISHED",
        "tsa_certificate_revocation": "NOT_CHECKED",
        "historical_revocation_assurance": "NOT_ESTABLISHED",
        "timestamp_authentication": "CRYPTOGRAPHICALLY_VALID_RELATIVE_TO_CALLER_ANCHOR" if verified else "NOT_ESTABLISHED",
        "event_truth": "NOT_ESTABLISHED",
        "verification_engine": "OpenSSL ts -verify",
        "verification_error": None if verified else (completed.stderr.strip() or completed.stdout.strip() or "OpenSSL rejected the timestamp token."),
        "interpretation": (
            "VALID means OpenSSL accepted the RFC 3161 token signature, message "
            "imprint, timestamping certificate purpose and certificate path at "
            "the token's asserted genTime, relative to the exact caller-supplied "
            "and digest-pinned trust-anchor PEM. The pin does not authenticate "
            "the anchor's issuer or delivery channel. The TSA's time assertion "
            "and the truth of the underlying event are not independently proven."
        ),
    }
