"""Small, synthetic demonstration of the ∂ss address-resolution control loop.

This is an illustrative reference implementation, not a production address matcher.
It uses fictional data and deliberately conservative rules.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


FIELDS = ("premise", "street", "locality", "postcode")


def normalise(value: Any) -> str:
    """Normalise case and repeated whitespace; do not discard identity-bearing text."""
    return " ".join(str(value or "").casefold().split())


def required_fields_present(record: dict[str, Any]) -> bool:
    return all(normalise(record.get(field)) for field in FIELDS)


def same_record(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        required_fields_present(left)
        and required_fields_present(right)
        and all(normalise(left.get(field)) == normalise(right.get(field)) for field in FIELDS)
    )


def edit_distance_at_most_one(left: str, right: str) -> bool:
    """Return whether two strings have Levenshtein distance <= 1."""
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
            str(intended.get("street", "")), str(observed.get("street", ""))
        ),
    }
    return {"passed": all(checks.values()), "checks": checks}


def finalise_trace(trace: dict[str, Any]) -> dict[str, Any]:
    """Attach the shared evidence classification used by the experiment bench."""
    reason = trace.get("reason_code", "UNSPECIFIED")
    if reason in {"EXACT_IDENTITY_FIELDS", "UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED"}:
        evidence_class = "SUFFICIENT_AND_CONSISTENT"
    elif reason in {"MISSING_REQUIRED_INTENDED_FIELD", "NO_SUPPORTED_CANDIDATE"}:
        evidence_class = "INSUFFICIENT"
    elif reason in {"MULTIPLE_EXACT_CANDIDATES", "AMBIGUOUS_CANDIDATES"}:
        evidence_class = "AMBIGUOUS"
    elif reason == "RETURN_CHECK_FAILED":
        evidence_class = "CONFLICTING"
    else:
        evidence_class = "INSUFFICIENT"
    trace["evidence_class"] = evidence_class
    trace["reason_codes"] = [reason]
    return trace


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    intended = case["intended"]
    candidates = case.get("candidates", [])

    trace: dict[str, Any] = {
        "case_id": case["case_id"],
        "intended": intended,
        "candidate_count": len(candidates),
        "candidate_ids": [c.get("candidate_id", f"candidate-{i+1}") for i, c in enumerate(candidates)],
        "selected_candidate": None,
        "operation": "NONE",
        "return_check": None,
    }

    if not required_fields_present(intended):
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "MISSING_REQUIRED_INTENDED_FIELD",
        })
        return finalise_trace(trace)

    exact = [c for c in candidates if same_record(intended, c)]
    if len(exact) == 1:
        trace.update({
            "selected_candidate": exact[0].get("candidate_id"),
            "operation": "NO_CHANGE",
            "return_check": return_check(intended, exact[0]),
            "terminal_state": "VERIFIED",
            "reason_code": "EXACT_IDENTITY_FIELDS",
        })
        return trace
    if len(exact) > 1:
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "MULTIPLE_EXACT_CANDIDATES",
        })
        return trace

    # Candidate retrieval is intentionally permissive enough to expose the
    # return-check gate: same premise/locality and a street within one edit.
    near = [
        c for c in candidates
        if required_fields_present(c)
        and normalise(intended.get("premise")) == normalise(c.get("premise"))
        and normalise(intended.get("locality")) == normalise(c.get("locality"))
        and edit_distance_at_most_one(
            str(intended.get("street", "")), str(c.get("street", ""))
        )
    ]

    if len(near) == 0:
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "NO_SUPPORTED_CANDIDATE",
        })
        return trace
    if len(near) > 1:
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "AMBIGUOUS_CANDIDATES",
        })
        return trace

    selected = near[0]
    check = return_check(intended, selected)
    trace["selected_candidate"] = selected.get("candidate_id")
    trace["operation"] = "PROPOSE_CANONICAL_CANDIDATE"
    trace["return_check"] = check

    if not check["passed"]:
        trace.update({
            "terminal_state": "UNRESOLVED",
            "reason_code": "RETURN_CHECK_FAILED",
        })
        return trace

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
    for trace in traces:
        print(f'{trace["case_id"]:<22} {trace["terminal_state"]:<10} {trace["reason_code"]}')
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
