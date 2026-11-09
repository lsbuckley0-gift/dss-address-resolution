"""Small, synthetic demonstration of the ∂ss address-resolution control loop.

This is an illustrative reference implementation, not a production address matcher.
It uses fictional data and deliberately conservative rules.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Make the repository-level shared contract importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dss_core.evidence import classify_evidence


FIELDS = ("premise", "street", "locality", "postcode")
RULESET_VERSION = "synthetic-address-demo/1.0"
NORMALISATION_RULE = "text-only Unicode casefold plus whitespace collapse"


def normalise(value: Any) -> str:
    """Normalise text only; malformed non-string values are never coerced to identity."""
    if not isinstance(value, str):
        return ""
    return " ".join(value.casefold().split())


def required_fields_present(record: Any) -> bool:
    return isinstance(record, dict) and all(
        normalise(record.get(field)) for field in FIELDS
    )


def same_record(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        required_fields_present(left)
        and required_fields_present(right)
        and all(normalise(left.get(field)) == normalise(right.get(field)) for field in FIELDS)
    )


def edit_distance_at_most_one(left: str, right: str) -> bool:
    """Return whether two strings have Levenshtein distance <= 1."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    a, b = normalise(left), normalise(right)
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
    if j < len(b) or i < len(a):
        differences += 1
    return differences <= 1


def return_check(intended: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    """Check protected fields exactly and allow at most one street edit."""
    checks = {
        "premise": normalise(intended.get("premise")) == normalise(observed.get("premise")),
        "locality": normalise(intended.get("locality")) == normalise(observed.get("locality")),
        "postcode": normalise(intended.get("postcode")) == normalise(observed.get("postcode")),
        "street_within_one_edit": edit_distance_at_most_one(
            intended.get("street", ""), observed.get("street", "")
        ),
    }
    return {"passed": all(checks.values()), "checks": checks}


def finalise_trace(trace: dict[str, Any]) -> dict[str, Any]:
    """Attach the shared evidence classification to an address decision trace."""
    reason = trace.get("reason_code", "UNSPECIFIED")
    if reason in {"EXACT_IDENTITY_FIELDS", "UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED"}:
        evidence_class = classify_evidence()
    elif reason in {
        "MISSING_REQUIRED_INTENDED_FIELD", "NO_SUPPORTED_CANDIDATE",
        "MALFORMED_CASE", "MALFORMED_INTENDED_RECORD",
        "MALFORMED_CANDIDATE_COLLECTION", "MALFORMED_CANDIDATE_RECORD",
    }:
        evidence_class = classify_evidence(missing=True)
    elif reason in {"MULTIPLE_EXACT_CANDIDATES", "AMBIGUOUS_CANDIDATES"}:
        evidence_class = classify_evidence(ambiguous=True)
    elif reason == "RETURN_CHECK_FAILED":
        evidence_class = classify_evidence(conflicting=True)
    else:
        evidence_class = classify_evidence(missing=True)
    trace["evidence_class"] = evidence_class
    trace["reason_codes"] = [reason]
    # A deterministic trace key for this synthetic demo, not a signature,
    # content-integrity proof or production audit identifier.
    identity = {
        "case_id": trace.get("case_id") if isinstance(trace.get("case_id"), str) else None,
        "candidate_ids": trace.get("candidate_ids", []),
        "candidate_count": trace.get("candidate_count", 0),
        "terminal_state": trace.get("terminal_state"),
        "reason_code": reason,
    }
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    trace["trace_id"] = "addr-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]
    trace["ruleset_version"] = RULESET_VERSION
    trace["normalisation_rule"] = NORMALISATION_RULE
    return trace


def candidate_comparison(intended: Any, candidate: Any, candidate_id: str, candidate_index: int) -> dict[str, Any]:
    """Expose field evidence without coercing malformed values into address text."""
    comparisons: dict[str, Any] = {}
    for field in FIELDS:
        intended_value = intended.get(field) if isinstance(intended, dict) else None
        candidate_value = candidate.get(field) if isinstance(candidate, dict) else None
        intended_valid = isinstance(intended_value, str) and bool(normalise(intended_value))
        candidate_valid = isinstance(candidate_value, str) and bool(normalise(candidate_value))
        comparisons[field] = {
            "intended_value": intended_value,
            "candidate_value": candidate_value,
            "both_text_and_nonblank": intended_valid and candidate_valid,
            "intended_normalised": normalise(intended_value) if intended_valid else None,
            "candidate_normalised": normalise(candidate_value) if candidate_valid else None,
            "normalised_equal": (
                normalise(intended_value) == normalise(candidate_value)
                if intended_valid and candidate_valid else None
            ),
        }

    valid_candidate = required_fields_present(candidate)
    premise_match = comparisons["premise"]["normalised_equal"] is True
    street_near = (
        edit_distance_at_most_one(intended.get("street", ""), candidate.get("street", ""))
        if isinstance(intended, dict) and valid_candidate else False
    )
    locality_match = comparisons["locality"]["normalised_equal"] is True
    postcode_match = comparisons["postcode"]["normalised_equal"] is True
    retrieval_eligible = valid_candidate and premise_match and locality_match and street_near
    retrieval_reasons = []
    if not valid_candidate:
        retrieval_reasons.append("CANDIDATE_MISSING_OR_INVALID_REQUIRED_FIELD")
    if not premise_match:
        retrieval_reasons.append("PREMISE_MISMATCH")
    if not locality_match:
        retrieval_reasons.append("LOCALITY_MISMATCH")
    if not street_near:
        retrieval_reasons.append("STREET_OUTSIDE_ONE_EDIT_RETRIEVAL_RULE")
    return {
        "candidate_id": candidate_id,
        "candidate_index": candidate_index,
        "field_comparisons": comparisons,
        "street_edit_distance_at_most_one": street_near,
        "retrieval": {
            "eligible": retrieval_eligible,
            "reason_codes": retrieval_reasons or ["RETRIEVAL_RULES_PASSED"],
        },
        "protected_field_checks": {
            "premise": premise_match,
            "locality": locality_match,
            "postcode": postcode_match,
        },
        "disposition": "PENDING",
        "reason_codes": [],
    }


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

    return {
        "valid": not mismatches,
        "mismatches": mismatches,
        "candidate_count": expected_count,
        "field_comparison_count": field_comparison_count,
    }


def evaluate_case(case: Any) -> dict[str, Any]:
    """Evaluate one synthetic case and expose evidence for every supplied candidate."""
    if not isinstance(case, dict):
        return finalise_trace({
            "case_id": None, "intended": None, "candidate_count": 0,
            "candidate_ids": [], "candidate_trace": [], "selected_candidate": None,
            "selected_candidate_index": None, "operation": "NONE", "return_check": None,
            "terminal_state": "UNRESOLVED", "reason_code": "MALFORMED_CASE",
        })

    intended = case.get("intended")
    raw_candidates = case.get("candidates", [])
    candidates = raw_candidates if isinstance(raw_candidates, list) else []
    candidate_ids = [
        (
            candidate.get("candidate_id")
            if isinstance(candidate, dict)
            and isinstance(candidate.get("candidate_id"), str)
            and candidate.get("candidate_id").strip()
            else f"candidate-{index + 1}"
        )
        for index, candidate in enumerate(candidates)
    ]
    candidate_trace = [
        (
            candidate_comparison(intended, candidate, candidate_ids[index], index)
            if isinstance(candidate, dict)
            else {
                "candidate_id": candidate_ids[index],
                "candidate_index": index,
                "field_comparisons": {},
                "street_edit_distance_at_most_one": False,
                "retrieval": {
                    "eligible": False,
                    "reason_codes": ["MALFORMED_CANDIDATE_RECORD"],
                },
                "protected_field_checks": {
                    "premise": False, "locality": False, "postcode": False,
                },
                "disposition": "REFUSED",
                "reason_codes": ["MALFORMED_CANDIDATE_RECORD"],
            }
        )
        for index, candidate in enumerate(candidates)
    ]
    trace: dict[str, Any] = {
        "case_id": case.get("case_id"),
        "intended": intended,
        "candidate_count": len(raw_candidates) if isinstance(raw_candidates, list) else 0,
        "candidate_ids": candidate_ids,
        "candidate_trace": candidate_trace,
        "selected_candidate": None,
        "selected_candidate_index": None,
        "operation": "NONE",
        "return_check": None,
    }

    if not isinstance(intended, dict):
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "MALFORMED_INTENDED_RECORD",
        })
        for item in candidate_trace:
            if item["disposition"] == "PENDING":
                item.update(disposition="REFUSED", reason_codes=["INTENDED_RECORD_MALFORMED"])
        return finalise_trace(trace)

    if not isinstance(raw_candidates, list):
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "MALFORMED_CANDIDATE_COLLECTION",
        })
        return finalise_trace(trace)

    if any(not isinstance(candidate, dict) for candidate in raw_candidates):
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "MALFORMED_CANDIDATE_RECORD",
        })
        for item in candidate_trace:
            if item["disposition"] == "PENDING":
                item.update(disposition="REFUSED", reason_codes=["MALFORMED_CANDIDATE_PRESENT"])
        return finalise_trace(trace)

    if not required_fields_present(intended):
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "MISSING_REQUIRED_INTENDED_FIELD",
        })
        for item in candidate_trace:
            item.update(disposition="REFUSED", reason_codes=["INTENDED_REQUIRED_FIELD_MISSING"])
        return finalise_trace(trace)

    exact_indices = [
        index for index, candidate in enumerate(candidates)
        if same_record(intended, candidate)
    ]
    if len(exact_indices) == 1:
        index = exact_indices[0]
        selected = candidates[index]
        candidate_trace[index].update(
            disposition="SELECTED_EXACT",
            reason_codes=["ALL_IDENTITY_FIELDS_MATCH"],
        )
        for other_index, item in enumerate(candidate_trace):
            if other_index != index:
                item.update(
                    disposition="NOT_SELECTED",
                    reason_codes=item["retrieval"]["reason_codes"],
                )
        trace.update({
            "selected_candidate": candidate_ids[index],
            "selected_candidate_index": index,
            "operation": "NO_CHANGE",
            "return_check": return_check(intended, selected),
            "terminal_state": "VERIFIED",
            "reason_code": "EXACT_IDENTITY_FIELDS",
        })
        return finalise_trace(trace)
    if len(exact_indices) > 1:
        for item in candidate_trace:
            if item["field_comparisons"] and all(
                item["field_comparisons"][field]["normalised_equal"] is True for field in FIELDS
            ):
                item.update(disposition="AMBIGUOUS_EXACT", reason_codes=["MULTIPLE_EXACT_CANDIDATES"])
            else:
                item.update(disposition="NOT_SELECTED", reason_codes=item["retrieval"]["reason_codes"])
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "MULTIPLE_EXACT_CANDIDATES",
        })
        return finalise_trace(trace)

    near_indices = [
        index for index, item in enumerate(candidate_trace)
        if item["retrieval"]["eligible"]
    ]
    for index, item in enumerate(candidate_trace):
        if index not in near_indices:
            item.update(
                disposition="REFUSED_RETRIEVAL",
                reason_codes=item["retrieval"]["reason_codes"],
            )

    if len(near_indices) == 0:
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "NO_SUPPORTED_CANDIDATE",
        })
        return finalise_trace(trace)
    if len(near_indices) > 1:
        for index in near_indices:
            candidate_trace[index].update(
                disposition="AMBIGUOUS",
                reason_codes=["MULTIPLE_RETRIEVAL_ELIGIBLE_CANDIDATES"],
            )
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "AMBIGUOUS_CANDIDATES",
        })
        return finalise_trace(trace)

    index = near_indices[0]
    selected = candidates[index]
    check = return_check(intended, selected)
    candidate_trace[index].update(
        disposition="SELECTED_FOR_RETURN_CHECK",
        reason_codes=["UNIQUE_RETRIEVAL_ELIGIBLE_CANDIDATE"],
    )
    trace["selected_candidate"] = candidate_ids[index]
    trace["selected_candidate_index"] = index
    trace["operation"] = "PROPOSE_CANONICAL_CANDIDATE"
    trace["return_check"] = check

    if not check["passed"]:
        failed = [field.upper() for field, passed in check["checks"].items() if not passed]
        candidate_trace[index].update(
            disposition="REFUSED_RETURN_CHECK",
            reason_codes=["RETURN_CHECK_FAILED"] + [f"{field}_RETURN_MISMATCH" for field in failed],
        )
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "RETURN_CHECK_FAILED",
        })
        return finalise_trace(trace)

    candidate_trace[index].update(
        disposition="SELECTED_CORRECTED",
        reason_codes=["UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED"],
    )
    trace.update({
        "terminal_state": "CORRECTED",
        "reason_code": "UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED",
    })
    return finalise_trace(trace)

def run(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [evaluate_case(case) for case in cases]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the synthetic ∂ss address-resolution demo.")
    parser.add_argument(
        "--cases",
        default=str(Path(__file__).with_name("cases.json")),
        help="Path to a JSON file containing synthetic cases.",
    )
    parser.add_argument("--json-out", help="Optional path for machine-readable trace output.")
    args = parser.parse_args()

    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    traces = run(cases)
    audits = [
        audit_candidate_trace(case, trace)
        for case, trace in zip(cases, traces)
    ]
    invalid_audits = [
        {"case_id": trace.get("case_id"), "mismatches": audit["mismatches"]}
        for trace, audit in zip(traces, audits) if not audit["valid"]
    ]
    if invalid_audits:
        print("Candidate trace audit failed:", json.dumps(invalid_audits, sort_keys=True))
        raise SystemExit(1)
    audited_candidates = sum(audit["candidate_count"] for audit in audits)
    print(
        f"Candidate trace audit: {len(audits)} valid cases, "
        f"{audited_candidates} candidate entries checked"
    )
    for trace in traces:
        print(f'{trace["case_id"]:<22} {trace["terminal_state"]:<10} {trace["reason_code"]:<48} {trace["trace_id"]} {trace["ruleset_version"]}')
    counts: dict[str, int] = {}
    for trace in traces:
        state = trace["terminal_state"]
        counts[state] = counts.get(state, 0) + 1
    print("\nSummary:", json.dumps(counts, sort_keys=True))

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(traces, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"Trace written to {args.json_out}")


if __name__ == "__main__":
    main()
