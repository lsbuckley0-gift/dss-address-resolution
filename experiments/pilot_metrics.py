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
OUTCOME_CLASSES = (
    "CORRECT_AUTO_RESOLUTION",
    "FALSE_ACCEPT",
    "FALSE_REJECT",
    "CORRECT_ABSTENTION",
)


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


def _reject_extra_fields(value, allowed, location):
    extra = set(value) - allowed
    if extra:
        names = ", ".join(sorted(repr(key) for key in extra))
        raise ValueError(f"{location} contains unsupported field(s): {names}.")


def _validate(data):
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise ValueError("Input must be an object containing a cases array.")
    _reject_extra_fields(
        data, {"dataset_id", "dataset_version", "cases"}, "input"
    )
    for field in ("dataset_id", "dataset_version"):
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string.")
    if not data["cases"]:
        raise ValueError("Evaluation requires at least one paired case.")
    seen = set()
    for index, case in enumerate(data["cases"]):
        prefix = f"cases[{index}]"
        if not isinstance(case, dict):
            raise ValueError(f"{prefix} must be an object.")
        _reject_extra_fields(
            case,
            {"case_id", "gold_candidate_id", "baseline", "dss"},
            prefix,
        )
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"{prefix}.case_id must be a non-empty string.")
        if case_id in seen:
            raise ValueError(f"Duplicate case_id: {case_id}")
        seen.add(case_id)
        if "gold_candidate_id" not in case:
            raise ValueError(f"{prefix}.gold_candidate_id is required; use null only when no unique answer exists.")
        gold = case["gold_candidate_id"]
        if gold is not None and (not isinstance(gold, str) or not gold.strip()):
            raise ValueError(f"{prefix}.gold_candidate_id must be a non-empty string or null.")
        for system in SYSTEMS:
            decision = case.get(system)
            if not isinstance(decision, dict):
                raise ValueError(f"{prefix}.{system} must be an object.")
            _reject_extra_fields(
                decision,
                {
                    "terminal_state", "selected_candidate_id", "trace_complete",
                    "review_routed", "latency_ms", "review_seconds",
                },
                f"{prefix}.{system}",
            )
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
            if not isinstance(decision.get("review_routed"), bool):
                raise ValueError(f"{prefix}.{system}.review_routed must be boolean.")
            if decision["review_routed"] and decision["terminal_state"] != "UNRESOLVED":
                raise ValueError(f"{prefix}.{system}: only unresolved cases may be routed to review.")
            for metric in ("latency_ms", "review_seconds"):
                value = decision.get(metric)
                if value is not None and (
                    isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value < 0
                ):
                    raise ValueError(f"{prefix}.{system}.{metric} must be a finite non-negative number.")
            if decision.get("review_seconds") is not None and not decision["review_routed"]:
                raise ValueError(f"{prefix}.{system}: review_seconds requires review_routed=true.")


def _outcome_class(case, system):
    decision = case[system]
    if decision["terminal_state"] == "UNRESOLVED":
        return "FALSE_REJECT" if case["gold_candidate_id"] is not None else "CORRECT_ABSTENTION"
    if (case["gold_candidate_id"] is not None and
            decision["selected_candidate_id"] == case["gold_candidate_id"]):
        return "CORRECT_AUTO_RESOLUTION"
    return "FALSE_ACCEPT"


def _paired_outcome_matrix(cases):
    matrix = {
        baseline: {dss: 0 for dss in OUTCOME_CLASSES}
        for baseline in OUTCOME_CLASSES
    }
    for case in cases:
        matrix[_outcome_class(case, "baseline")][_outcome_class(case, "dss")] += 1
    return matrix


def _system_metrics(cases, system):
    total = len(cases)
    accepted = [c for c in cases if c[system]["terminal_state"] != "UNRESOLVED"]
    corrected = [c for c in cases if c[system]["terminal_state"] == "CORRECTED"]
    false_accepts = [c for c in accepted if c["gold_candidate_id"] is None or
                     c[system]["selected_candidate_id"] != c["gold_candidate_id"]]
    correct = len(accepted) - len(false_accepts)
    unresolved = total - len(accepted)
    unique_gold_cases = [c for c in cases if c["gold_candidate_id"] is not None]
    false_rejects = [c for c in unique_gold_cases
                     if c[system]["terminal_state"] == "UNRESOLVED"]
    correct_abstentions = sum(
        c["gold_candidate_id"] is None and c[system]["terminal_state"] == "UNRESOLVED"
        for c in cases
    )
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
        "unique_gold_cases": len(unique_gold_cases),
        "false_rejects": len(false_rejects),
        "false_reject_rate": (len(false_rejects) / len(unique_gold_cases)) if unique_gold_cases else None,
        "false_reject_rate_95pct_wilson": _wilson(len(false_rejects), len(unique_gold_cases)),
        "false_reject_prevalence": len(false_rejects) / total if total else None,
        "correct_abstentions": correct_abstentions,
        "correct_auto_resolution_rate": correct / total if total else None,
        "coverage": len(accepted) / total if total else None,
        "unresolved": unresolved,
        "unresolved_rate": unresolved / total if total else None,
        "corrections": len(corrected),
        "correct_corrections": len(corrected) - len(corrected_false),
        "correction_precision": (len(corrected) - len(corrected_false)) / len(corrected) if corrected else None,
        "review_routed_cases": sum(c[system]["review_routed"] for c in cases),
        "review_cases_with_time": len(reviews),
        "review_time_measurement_coverage": (len(reviews) / sum(c[system]["review_routed"] for c in cases)) if any(c[system]["review_routed"] for c in cases) else None,
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
        "report_version": "paired-pilot-metrics/1.2",
        "dataset_id": data.get("dataset_id"),
        "dataset_version": data.get("dataset_version"),
        "case_count": len(cases),
        "systems": {system: _system_metrics(cases, system) for system in SYSTEMS},
        "paired_case_count": len(cases),
        "paired_outcome_matrix": _paired_outcome_matrix(cases),
        "method_notes": [
            "A decision is automatically accepted when terminal_state is VERIFIED or CORRECTED.",
            "A false accept is any automatic acceptance whose selected candidate differs from the gold candidate, including cases labelled with no unique answer.",
            "False-accept rate denominator is all automatic acceptances; prevalence denominator is all cases.",
            "A false reject is an unresolved decision on a case with a non-null unique gold candidate; its rate denominator is all cases with a unique gold label.",
            "A correct abstention is an unresolved decision on a case whose gold candidate is null; false-reject prevalence uses all cases as its denominator.",
            "The paired outcome matrix places each case once at the intersection of its baseline and dss outcome classes, exposing case-level trade-offs without treating the systems as independent samples.",
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
