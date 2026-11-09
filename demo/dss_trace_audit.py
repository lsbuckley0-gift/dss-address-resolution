"""Independent integrity audit for synthetic address candidate traces.

This module deliberately does not import or call the address evaluator.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

FIELDS = ("premise", "street", "locality", "postcode")
RULESET_VERSION = "synthetic-address-demo/1.0"
TRACE_SCHEMA_VERSION = "candidate-trace/1.0"
NORMALISATION_RULE = "text-only Unicode casefold plus whitespace collapse"

def _audit_normalise(value: Any) -> str:
    """Independent audit-side normalisation; do not trust emitted trace values."""
    return " ".join(value.casefold().split()) if isinstance(value, str) else ""


def _audit_edit_at_most_one(left: Any, right: Any) -> bool:
    """Independent audit-side Levenshtein <= 1 check."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    a, b = _audit_normalise(left), _audit_normalise(right)
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = differences = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        differences += 1
        if differences > 1:
            return False
        if len(a) == len(b):
            i += 1
        j += 1
    if i < len(a) or j < len(b):
        differences += 1
    return differences <= 1


def audit_candidate_trace(case: Any, trace: Any) -> dict[str, Any]:
    """Independently check candidate evidence values and positional references.

    This audits trace integrity, not the scientific validity of the demo rules or
    a production address decision.
    """
    mismatches: list[str] = []
    if not isinstance(case, dict) or not isinstance(trace, dict):
        return {
            "valid": False,
            "mismatches": ["MALFORMED_CASE_OR_TRACE"],
            "candidate_count": 0,
            "field_comparison_count": 0,
        }

    intended = case.get("intended")
    if trace.get("intended") != intended:
        mismatches.append("INTENDED_RECORD_MISMATCH")
    raw_candidates = case.get("candidates", [])
    candidates = raw_candidates if isinstance(raw_candidates, list) else []
    expected_ids = []
    for index, candidate in enumerate(candidates):
        supplied_id = (
            candidate.get("candidate_id")
            if isinstance(candidate, dict) else None
        )
        expected_ids.append(
            supplied_id if isinstance(supplied_id, str) and supplied_id.strip()
            else f"candidate-{index + 1}"
        )

    if trace.get("case_id") != case.get("case_id"):
        mismatches.append("CASE_ID_MISMATCH")
    expected_count = len(candidates)
    observed_count = trace.get("candidate_count")
    if not isinstance(observed_count, int) or isinstance(observed_count, bool) or observed_count != expected_count:
        mismatches.append("CANDIDATE_COUNT_MISMATCH")
    if trace.get("candidate_ids") != expected_ids:
        mismatches.append("CANDIDATE_ID_LIST_MISMATCH")

    entries = trace.get("candidate_trace")
    if not isinstance(entries, list):
        entries = []
        mismatches.append("CANDIDATE_TRACE_NOT_A_LIST")
    if len(entries) != expected_count:
        mismatches.append("CANDIDATE_TRACE_COUNT_MISMATCH")

    field_comparison_count = 0
    expected_retrieval_flags: list[bool] = []
    expected_exact_flags: list[bool] = []
    expected_street_flags: list[bool] = []
    for index, candidate in enumerate(candidates):
        if index >= len(entries):
            continue
        entry = entries[index]
        if not isinstance(entry, dict):
            mismatches.append(f"CANDIDATE_ENTRY_NOT_AN_OBJECT:{index}")
            continue
        observed_index = entry.get("candidate_index")
        if (
            not isinstance(observed_index, int) or isinstance(observed_index, bool)
            or observed_index != index
        ):
            mismatches.append(f"CANDIDATE_POSITION_MISMATCH:{index}")
        if entry.get("candidate_id") != expected_ids[index]:
            mismatches.append(f"CANDIDATE_LABEL_MISMATCH:{index}")

        if not isinstance(candidate, dict):
            expected_fields = {}
            expected_retrieval = {
                "eligible": False,
                "reason_codes": ["MALFORMED_CANDIDATE_RECORD"],
            }
            expected_protected = {"premise": False, "locality": False, "postcode": False}
            expected_retrieval_flags.append(False)
            expected_exact_flags.append(False)
            expected_street_flags.append(False)
        else:
            expected_fields = {}
            for field in FIELDS:
                intended_value = intended.get(field) if isinstance(intended, dict) else None
                candidate_value = candidate.get(field)
                intended_valid = (
                    isinstance(intended_value, str) and bool(_audit_normalise(intended_value))
                )
                candidate_valid = (
                    isinstance(candidate_value, str) and bool(_audit_normalise(candidate_value))
                )
                expected_fields[field] = {
                    "intended_value": intended_value,
                    "candidate_value": candidate_value,
                    "both_text_and_nonblank": intended_valid and candidate_valid,
                    "intended_normalised": _audit_normalise(intended_value) if intended_valid else None,
                    "candidate_normalised": _audit_normalise(candidate_value) if candidate_valid else None,
                    "normalised_equal": (
                        _audit_normalise(intended_value) == _audit_normalise(candidate_value)
                        if intended_valid and candidate_valid else None
                    ),
                }
            valid_candidate = all(
                isinstance(candidate.get(field), str) and bool(_audit_normalise(candidate.get(field)))
                for field in FIELDS
            )
            premise_match = expected_fields["premise"]["normalised_equal"] is True
            locality_match = expected_fields["locality"]["normalised_equal"] is True
            postcode_match = expected_fields["postcode"]["normalised_equal"] is True
            street_near = (
                _audit_edit_at_most_one(intended.get("street", ""), candidate.get("street", ""))
                if isinstance(intended, dict) and valid_candidate else False
            )
            retrieval_reasons = []
            if not valid_candidate:
                retrieval_reasons.append("CANDIDATE_MISSING_OR_INVALID_REQUIRED_FIELD")
            if not premise_match:
                retrieval_reasons.append("PREMISE_MISMATCH")
            if not locality_match:
                retrieval_reasons.append("LOCALITY_MISMATCH")
            if not street_near:
                retrieval_reasons.append("STREET_OUTSIDE_ONE_EDIT_RETRIEVAL_RULE")
            expected_retrieval = {
                "eligible": valid_candidate and premise_match and locality_match and street_near,
                "reason_codes": retrieval_reasons or ["RETRIEVAL_RULES_PASSED"],
            }
            expected_protected = {
                "premise": premise_match,
                "locality": locality_match,
                "postcode": postcode_match,
            }
            expected_retrieval_flags.append(expected_retrieval["eligible"])
            expected_exact_flags.append(all(
                expected_fields[field]["normalised_equal"] is True for field in FIELDS
            ))
            expected_street_flags.append(street_near)

        observed_fields = entry.get("field_comparisons")
        if observed_fields != expected_fields:
            mismatches.append(f"FIELD_COMPARISON_MISMATCH:{index}")
        field_comparison_count += len(expected_fields)
        if entry.get("retrieval") != expected_retrieval:
            mismatches.append(f"RETRIEVAL_EVIDENCE_MISMATCH:{index}")
        if entry.get("protected_field_checks") != expected_protected:
            mismatches.append(f"PROTECTED_FIELD_CHECK_MISMATCH:{index}")
        if entry.get("disposition") in (None, "PENDING"):
            mismatches.append(f"NON_TERMINAL_CANDIDATE_DISPOSITION:{index}")
        reason_codes = entry.get("reason_codes")
        if not isinstance(reason_codes, list) or not reason_codes:
            mismatches.append(f"CANDIDATE_REASON_CODES_MISSING:{index}")

    expected_reason = None
    expected_terminal = "UNRESOLVED"
    expected_selected_index = None

    intended_valid = (
        isinstance(intended, dict)
        and all(
            isinstance(intended.get(field), str)
            and bool(_audit_normalise(intended.get(field)))
            for field in FIELDS
        )
    )
    if not isinstance(intended, dict):
        expected_reason = "MALFORMED_INTENDED_RECORD"
    elif not isinstance(raw_candidates, list):
        expected_reason = "MALFORMED_CANDIDATE_COLLECTION"
    elif any(not isinstance(candidate, dict) for candidate in raw_candidates):
        expected_reason = "MALFORMED_CANDIDATE_RECORD"
    elif not intended_valid:
        expected_reason = "MISSING_REQUIRED_INTENDED_FIELD"
    elif len(expected_exact_flags) == expected_count:
        exact_indices = [
            index for index, matched in enumerate(expected_exact_flags) if matched
        ]
        near_indices = [
            index for index, eligible in enumerate(expected_retrieval_flags) if eligible
        ]
        if len(exact_indices) == 1:
            expected_reason = "EXACT_IDENTITY_FIELDS"
            expected_terminal = "VERIFIED"
            expected_selected_index = exact_indices[0]
        elif len(exact_indices) > 1:
            expected_reason = "MULTIPLE_EXACT_CANDIDATES"
        elif len(near_indices) == 0:
            expected_reason = "NO_SUPPORTED_CANDIDATE"
        elif len(near_indices) > 1:
            expected_reason = "AMBIGUOUS_CANDIDATES"
        else:
            expected_selected_index = near_indices[0]
            selected_candidate = candidates[expected_selected_index]
            return_passed = (
                _audit_normalise(intended.get("premise")) == _audit_normalise(selected_candidate.get("premise"))
                and _audit_normalise(intended.get("locality")) == _audit_normalise(selected_candidate.get("locality"))
                and _audit_normalise(intended.get("postcode")) == _audit_normalise(selected_candidate.get("postcode"))
                and expected_street_flags[expected_selected_index]
            )
            if return_passed:
                expected_reason = "UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED"
                expected_terminal = "CORRECTED"
            else:
                expected_reason = "RETURN_CHECK_FAILED"

    if expected_reason is not None:
        if trace.get("reason_code") != expected_reason:
            mismatches.append("AGGREGATE_REASON_CODE_MISMATCH")
        if trace.get("terminal_state") != expected_terminal:
            mismatches.append("AGGREGATE_TERMINAL_STATE_MISMATCH")
        if trace.get("selected_candidate_index") != expected_selected_index:
            mismatches.append("AGGREGATE_SELECTED_POSITION_MISMATCH")

        for index, candidate in enumerate(candidates):
            if index >= len(entries) or not isinstance(entries[index], dict):
                continue
            if expected_reason == "MALFORMED_CANDIDATE_RECORD":
                disposition = "REFUSED"
                reasons = (
                    ["MALFORMED_CANDIDATE_PRESENT"]
                    if isinstance(candidate, dict) else ["MALFORMED_CANDIDATE_RECORD"]
                )
            elif expected_reason == "MALFORMED_INTENDED_RECORD":
                disposition = "REFUSED"
                reasons = (
                    ["INTENDED_RECORD_MALFORMED"]
                    if isinstance(candidate, dict) else ["MALFORMED_CANDIDATE_RECORD"]
                )
            elif expected_reason == "MISSING_REQUIRED_INTENDED_FIELD":
                disposition = "REFUSED"
                reasons = ["INTENDED_REQUIRED_FIELD_MISSING"]
            elif expected_reason == "EXACT_IDENTITY_FIELDS":
                if index == expected_selected_index:
                    disposition, reasons = "SELECTED_EXACT", ["ALL_IDENTITY_FIELDS_MATCH"]
                else:
                    disposition, reasons = "NOT_SELECTED", entries[index]["retrieval"]["reason_codes"]
            elif expected_reason == "MULTIPLE_EXACT_CANDIDATES":
                if expected_exact_flags[index]:
                    disposition, reasons = "AMBIGUOUS_EXACT", ["MULTIPLE_EXACT_CANDIDATES"]
                else:
                    disposition, reasons = "NOT_SELECTED", entries[index]["retrieval"]["reason_codes"]
            elif expected_reason == "NO_SUPPORTED_CANDIDATE":
                disposition, reasons = "REFUSED_RETRIEVAL", entries[index]["retrieval"]["reason_codes"]
            elif expected_reason == "AMBIGUOUS_CANDIDATES":
                if expected_retrieval_flags[index]:
                    disposition, reasons = "AMBIGUOUS", ["MULTIPLE_RETRIEVAL_ELIGIBLE_CANDIDATES"]
                else:
                    disposition, reasons = "REFUSED_RETRIEVAL", entries[index]["retrieval"]["reason_codes"]
            elif expected_reason == "RETURN_CHECK_FAILED":
                if index == expected_selected_index:
                    selected_candidate = candidates[index]
                    failed = []
                    if _audit_normalise(intended.get("premise")) != _audit_normalise(selected_candidate.get("premise")):
                        failed.append("PREMISE_RETURN_MISMATCH")
                    if _audit_normalise(intended.get("locality")) != _audit_normalise(selected_candidate.get("locality")):
                        failed.append("LOCALITY_RETURN_MISMATCH")
                    if _audit_normalise(intended.get("postcode")) != _audit_normalise(selected_candidate.get("postcode")):
                        failed.append("POSTCODE_RETURN_MISMATCH")
                    if not expected_street_flags[index]:
                        failed.append("STREET_WITHIN_ONE_EDIT_RETURN_MISMATCH")
                    disposition, reasons = "REFUSED_RETURN_CHECK", ["RETURN_CHECK_FAILED"] + failed
                else:
                    disposition, reasons = "REFUSED_RETRIEVAL", entries[index]["retrieval"]["reason_codes"]
            elif expected_reason == "UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED":
                if index == expected_selected_index:
                    disposition, reasons = "SELECTED_CORRECTED", ["UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED"]
                else:
                    disposition, reasons = "REFUSED_RETRIEVAL", entries[index]["retrieval"]["reason_codes"]
            else:
                continue
            if entries[index].get("disposition") != disposition:
                mismatches.append(f"CANDIDATE_DISPOSITION_MISMATCH:{index}")
            if entries[index].get("reason_codes") != reasons:
                mismatches.append(f"CANDIDATE_REASON_CODE_MISMATCH:{index}")

    expected_operation = "NONE"
    expected_return_check = None
    if expected_reason == "EXACT_IDENTITY_FIELDS":
        expected_operation = "NO_CHANGE"
    elif expected_reason in {
        "UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED", "RETURN_CHECK_FAILED",
    }:
        expected_operation = "PROPOSE_CANONICAL_CANDIDATE"

    if expected_selected_index is not None and expected_reason in {
        "EXACT_IDENTITY_FIELDS", "UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED",
        "RETURN_CHECK_FAILED",
    }:
        selected = candidates[expected_selected_index]
        checks = {
            "premise": _audit_normalise(intended.get("premise")) == _audit_normalise(selected.get("premise")),
            "locality": _audit_normalise(intended.get("locality")) == _audit_normalise(selected.get("locality")),
            "postcode": _audit_normalise(intended.get("postcode")) == _audit_normalise(selected.get("postcode")),
            "street_within_one_edit": expected_street_flags[expected_selected_index],
        }
        expected_return_check = {"passed": all(checks.values()), "checks": checks}

    if trace.get("operation") != expected_operation:
        mismatches.append("OPERATION_MISMATCH")
    if trace.get("return_check") != expected_return_check:
        mismatches.append("RETURN_CHECK_MISMATCH")

    selected_index = trace.get("selected_candidate_index")
    selected_id = trace.get("selected_candidate")
    selected_dispositions = {
        "SELECTED_EXACT", "SELECTED_CORRECTED", "REFUSED_RETURN_CHECK",
    }
    observed_selected = [
        index for index, entry in enumerate(entries)
        if isinstance(entry, dict) and entry.get("disposition") in selected_dispositions
    ]
    if selected_index is None:
        if selected_id is not None or observed_selected:
            mismatches.append("SELECTED_CANDIDATE_REFERENCE_MISMATCH")
    elif (
        not isinstance(selected_index, int) or isinstance(selected_index, bool)
        or selected_index < 0 or selected_index >= len(expected_ids)
        or selected_id != expected_ids[selected_index]
        or observed_selected != [selected_index]
    ):
        mismatches.append("SELECTED_CANDIDATE_REFERENCE_MISMATCH")

    if trace.get("trace_schema_version") != TRACE_SCHEMA_VERSION:
        mismatches.append("TRACE_SCHEMA_VERSION_MISMATCH")
    if trace.get("ruleset_version") != RULESET_VERSION:
        mismatches.append("RULESET_VERSION_MISMATCH")
    if trace.get("normalisation_rule") != NORMALISATION_RULE:
        mismatches.append("NORMALISATION_RULE_MISMATCH")
    identity = {
        "case_id": case.get("case_id") if isinstance(case.get("case_id"), str) else None,
        "candidate_ids": expected_ids,
        "candidate_count": expected_count,
        "selected_candidate_index": trace.get("selected_candidate_index"),
        "trace_schema_version": TRACE_SCHEMA_VERSION,
        "ruleset_version": RULESET_VERSION,
        "normalisation_rule": NORMALISATION_RULE,
        "terminal_state": trace.get("terminal_state"),
        "reason_code": trace.get("reason_code"),
    }
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    expected_trace_id = "addr-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]
    if trace.get("trace_id") != expected_trace_id:
        mismatches.append("TRACE_ID_MISMATCH")

    return {
        "valid": not mismatches,
        "mismatches": mismatches,
        "candidate_count": expected_count,
        "field_comparison_count": field_comparison_count,
    }
