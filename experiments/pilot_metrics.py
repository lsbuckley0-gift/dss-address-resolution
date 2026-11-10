"""Paired pilot metrics for pseudonymous, case-level system decisions.

Input contains only case IDs, gold candidate IDs and decision metadata. Do not
put raw addresses or customer-identifying data in this file.
"""
from __future__ import annotations
import argparse
import json
import math
import statistics
from pathlib import Path

STATES = {"VERIFIED", "CORRECTED", "UNRESOLVED"}
SYSTEMS = ("baseline", "dss")


def _wilson(successes: int, total: int, z: float = 1.959963984540054):
    if total == 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return [max(0.0, centre - margin), min(1.0, centre + margin)]


def _percentile(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _validate(data):
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise ValueError("Input must be an object containing a cases array.")
    seen = set()
    for index, case in enumerate(data["cases"]):
        prefix = f"cases[{index}]"
        if not isinstance(case, dict):
            raise ValueError(f"{prefix} must be an object.")
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"{prefix}.case_id must be a non-empty string.")
        if case_id in seen:
            raise ValueError(f"Duplicate case_id: {case_id}")
        seen.add(case_id)
        gold = case.get("gold_candidate_id")
        if gold is not None and (not isinstance(gold, str) or not gold.strip()):
            raise ValueError(f"{prefix}.gold_candidate_id must be a non-empty string or null.")
        for system in SYSTEMS:
            decision = case.get(system)
            if not isinstance(decision, dict):
                raise ValueError(f"{prefix}.{system} must be an object.")
            if decision.get("terminal_state") not in STATES:
                raise ValueError(f"{prefix}.{system}.terminal_state is invalid.")
            selected = decision.get("selected_candidate_id")
            if selected is not None and (not isinstance(selected, str) or not selected.strip()):
                raise ValueError(f"{prefix}.{system}.selected_candidate_id must be a non-empty string or null.")
            if decision["terminal_state"] == "UNRESOLVED" and selected is not None:
                raise ValueError(f"{prefix}.{system}: UNRESOLVED must not select a candidate.")
            if decision["terminal_state"] != "UNRESOLVED" and selected is None:
                raise ValueError(f"{prefix}.{system}: accepted decisions require a selected candidate.")
            if not isinstance(decision.get("trace_complete"), bool):
                raise ValueError(f"{prefix}.{system}.trace_complete must be boolean.")
            for metric in ("latency_ms", "review_seconds"):
                value = decision.get(metric)
                if value is not None and (
                    isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value < 0
                ):
                    raise ValueError(f"{prefix}.{system}.{metric} must be a finite non-negative number.")
            if decision["terminal_state"] != "UNRESOLVED" and decision.get("review_seconds") is not None:
                raise ValueError(f"{prefix}.{system}: review_seconds is only valid for unresolved cases.")


def _system_metrics(cases, system):
    total = len(cases)
    accepted = [c for c in cases if c[system]["terminal_state"] != "UNRESOLVED"]
    corrected = [c for c in cases if c[system]["terminal_state"] == "CORRECTED"]
    false_accepts = [c for c in accepted if c["gold_candidate_id"] is None or
                     c[system]["selected_candidate_id"] != c["gold_candidate_id"]]
    correct = len(accepted) - len(false_accepts)
    unresolved = total - len(accepted)
    corrected_false = [c for c in corrected if c["gold_candidate_id"] is None or
                       c[system]["selected_candidate_id"] != c["gold_candidate_id"]]
    latencies = [c[system]["latency_ms"] for c in cases if c[system].get("latency_ms") is not None]
    reviews = [c[system]["review_seconds"] for c in cases if c[system].get("review_seconds") is not None]
    complete = sum(c[system]["trace_complete"] for c in cases)
    return {
        "cases": total,
        "auto_resolved": len(accepted),
        "correct_auto_resolved": correct,
        "false_accepts": len(false_accepts),
        "false_accept_rate": len(false_accepts) / len(accepted) if accepted else None,
        "false_accept_rate_95pct_wilson": _wilson(len(false_accepts), len(accepted)),
        "false_accept_prevalence": len(false_accepts) / total if total else None,
        "correct_auto_resolution_rate": correct / total if total else None,
        "coverage": len(accepted) / total if total else None,
        "unresolved": unresolved,
        "unresolved_rate": unresolved / total if total else None,
        "corrections": len(corrected),
        "correct_corrections": len(corrected) - len(corrected_false),
        "correction_precision": (len(corrected) - len(corrected_false)) / len(corrected) if corrected else None,
        "review_cases_with_time": len(reviews),
        "median_review_seconds": statistics.median(reviews) if reviews else None,
        "trace_complete": complete,
        "trace_completeness": complete / total if total else None,
        "latency_cases_with_measurement": len(latencies),
        "latency_median_ms": statistics.median(latencies) if latencies else None,
        "latency_p95_ms_nearest_rank": _percentile(latencies, 0.95),
    }


def evaluate(data):
    _validate(data)
    cases = data["cases"]
    return {
        "report_version": "paired-pilot-metrics/1.0",
        "dataset_id": data.get("dataset_id"),
        "dataset_version": data.get("dataset_version"),
        "case_count": len(cases),
        "systems": {system: _system_metrics(cases, system) for system in SYSTEMS},
        "paired_case_count": len(cases),
        "method_notes": [
            "A decision is automatically accepted when terminal_state is VERIFIED or CORRECTED.",
            "A false accept is any automatic acceptance whose selected candidate differs from the gold candidate, including cases labelled with no unique answer.",
            "False-accept rate denominator is all automatic acceptances; prevalence denominator is all cases.",
            "The 95% interval is the Wilson score interval; no interval is emitted when there are no automatic acceptances.",
            "Latency percentiles use nearest-rank; missing measurements are excluded and counted.",
            "Review time is summarised only for unresolved cases with a supplied review_seconds value.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON file containing paired, pseudonymous cases")
    parser.add_argument("--json-out", type=Path, help="Write report JSON to this path")
    args = parser.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        report = evaluate(data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.json_out:
        args.json_out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
