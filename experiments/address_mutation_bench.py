"""Deterministic synthetic mutation benchmark; oracle labels never enter evaluator input."""
from __future__ import annotations
import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from dss_demo import evaluate_case

BASE = {"premise": "14", "street": "King Street", "locality": "Fictionton", "postcode": "ZZ1 1ZZ"}
MUTATIONS = {
    "premise_conflict": ("premise", "41"),
    "street_one_edit": ("street", "King Stret"),
    "street_multiple_edits": ("street", "Kng Strret"),
    "locality_conflict": ("locality", "Elsewhere"),
    "postcode_conflict": ("postcode", "ZZ9 9ZZ"),
}

def _expected(mutations: tuple[str, ...]) -> tuple[str, str]:
    if not mutations or mutations == ("formatting_only",):
        return "VERIFIED", "EXACT_IDENTITY_FIELDS"
    if "premise_conflict" in mutations or "locality_conflict" in mutations:
        return "UNRESOLVED", "NO_SUPPORTED_CANDIDATE"
    if "postcode_conflict" in mutations:
        return "UNRESOLVED", "RETURN_CHECK_FAILED"
    if "street_multiple_edits" in mutations:
        return "UNRESOLVED", "NO_SUPPORTED_CANDIDATE"
    if "street_one_edit" in mutations:
        return "CORRECTED", "UNIQUE_CANDIDATE_AND_RETURN_CHECK_PASSED"
    raise AssertionError(mutations)

def build_dataset() -> list[dict[str, Any]]:
    scenarios = [
        ("clean-baseline", ()), ("formatting-only", ("formatting_only",)),
        ("premise-only", ("premise_conflict",)), ("street-one-edit-only", ("street_one_edit",)),
        ("street-multiple-edits-only", ("street_multiple_edits",)),
        ("locality-only", ("locality_conflict",)), ("postcode-only", ("postcode_conflict",)),
        ("premise-plus-street", ("premise_conflict", "street_one_edit")),
        ("premise-plus-postcode", ("premise_conflict", "postcode_conflict")),
        ("premise-plus-locality", ("premise_conflict", "locality_conflict")),
        ("street-plus-locality", ("street_one_edit", "locality_conflict")),
        ("street-plus-postcode", ("street_one_edit", "postcode_conflict")),
        ("locality-plus-postcode", ("locality_conflict", "postcode_conflict")),
    ]
    rows = []
    for label, mutations in scenarios:
        candidate = {"candidate_id": "synthetic-candidate", **deepcopy(BASE)}
        for mutation in mutations:
            if mutation == "formatting_only":
                candidate.update({"premise": " 14 ", "street": "KING   STREET",
                                  "locality": " FICTIONTON ", "postcode": "zz1 1zz"})
            else:
                field, value = MUTATIONS[mutation]
                candidate[field] = value
        state, reason = _expected(mutations)
        rows.append({"scenario": label, "mutations": list(mutations),
                     "expected_terminal_state": state, "expected_reason_code": reason,
                     "case": {"case_id": f"mutation-{len(rows)+1:02d}",
                              "intended": deepcopy(BASE), "candidates": [candidate]}})
    return rows

def benchmark() -> dict[str, Any]:
    records, mismatches, states, reasons = [], [], {}, {}
    false_accepts = 0
    for row in build_dataset():
        trace = evaluate_case(row["case"])
        state, reason = trace["terminal_state"], trace["reason_code"]
        states[state] = states.get(state, 0) + 1
        reasons[reason] = reasons.get(reason, 0) + 1
        identity_mutated = any(mutation != "formatting_only" for mutation in row["mutations"])
        if identity_mutated and state == "VERIFIED":
            false_accepts += 1
        if (state, reason) != (row["expected_terminal_state"], row["expected_reason_code"]):
            mismatches.append({"scenario": row["scenario"],
                "expected": [row["expected_terminal_state"], row["expected_reason_code"]],
                "observed": [state, reason]})
        records.append({"scenario": row["scenario"], "mutations": row["mutations"],
            "expected_terminal_state": row["expected_terminal_state"],
            "expected_reason_code": row["expected_reason_code"],
            "observed_terminal_state": state, "observed_reason_code": reason,
            "return_check_passed": trace["return_check"]["passed"]
                if isinstance(trace.get("return_check"), dict) else None})
    return {"benchmark": "synthetic-address-mutation-matrix", "synthetic_only": True,
        "case_count": len(records), "state_counts": dict(sorted(states.items())),
        "reason_code_counts": dict(sorted(reasons.items())),
        "mutated_false_accepts": false_accepts, "oracle_mismatches": mismatches,
        "passed": not mismatches and false_accepts == 0, "records": records}

def main() -> None:
    parser = argparse.ArgumentParser(description="Run the synthetic ∂ss address mutation benchmark.")
    parser.add_argument("--json-out", help="Optional machine-readable report path.")
    args = parser.parse_args()
    report = benchmark()
    print(json.dumps({k:v for k,v in report.items() if k != "records"}, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    if not report["passed"]:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
