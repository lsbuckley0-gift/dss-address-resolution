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
from dss_trace_audit import audit_candidate_trace


FIELDS = ("premise", "street", "locality", "postcode")
RULESET_VERSION = "synthetic-address-demo/1.0"
TRACE_SCHEMA_VERSION = "candidate-trace/1.0"
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
        "selected_candidate_index": trace.get("selected_candidate_index"),
        "trace_schema_version": TRACE_SCHEMA_VERSION,
        "ruleset_version": RULESET_VERSION,
        "normalisation_rule": NORMALISATION_RULE,
        "terminal_state": trace.get("terminal_state"),
        "reason_code": reason,
    }
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    trace["trace_id"] = "addr-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]
    trace["ruleset_version"] = RULESET_VERSION
    trace["trace_schema_version"] = TRACE_SCHEMA_VERSION
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
    parser.add_argument(
        "--candidate-detail",
        action="store_true",
        help="Print candidate-by-candidate field evidence and dispositions.",
    )
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
    for trace, audit in zip(traces, audits):
        trace["candidate_trace_audit"] = audit
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

    if args.candidate_detail:
        for trace in traces:
            print(f"\n{trace['case_id']} candidate evidence:")
            for candidate in trace["candidate_trace"]:
                reasons = ", ".join(candidate["reason_codes"])
                print(
                    f"  candidate {candidate['candidate_id']} "
                    f"[{candidate['candidate_index']}]: "
                    f"{candidate['disposition']} ({reasons})"
                )
                print(
                    f"    retrieval eligible: {candidate['retrieval']['eligible']}; "
                    f"protected checks: {json.dumps(candidate['protected_field_checks'], sort_keys=True)}"
                )
                for field, comparison in candidate["field_comparisons"].items():
                    print(
                        f"    {field}: intended "
                        f"{json.dumps(comparison['intended_value'], ensure_ascii=False)} "
                        f"-> {json.dumps(comparison['intended_normalised'], ensure_ascii=False)}; "
                        f"candidate {json.dumps(comparison['candidate_value'], ensure_ascii=False)} "
                        f"-> {json.dumps(comparison['candidate_normalised'], ensure_ascii=False)}; "
                        f"equal={comparison['normalised_equal']}"
                    )

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(traces, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"Trace written to {args.json_out}")


if __name__ == "__main__":
    main()
