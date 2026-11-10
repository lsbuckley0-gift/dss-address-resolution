"""Paired pilot metrics for pseudonymous, case-level system decisions.

Input contains only case IDs, gold candidate IDs and decision metadata. Do not
put raw addresses or customer-identifying data in this file.
"""
from __future__ import annotations
import argparse
import hashlib
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
STRATA = {
    "EXACT", "FORMATTING_ONLY", "TYPO", "DUPLICATE",
    "CONFLICTING", "INCOMPLETE", "STALE",
}


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
        data, {"dataset_id", "dataset_version", "cases", "sample_requirements", "decision_requirements", "primary_endpoint"}, "input"
    )
    for field in ("dataset_id", "dataset_version"):
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string.")
    if not data["cases"]:
        raise ValueError("Evaluation requires at least one paired case.")
    requirements = data.get("sample_requirements")
    if requirements is not None:
        if not isinstance(requirements, dict):
            raise ValueError("sample_requirements must be an object.")
        _reject_extra_fields(
            requirements,
            {"required_strata", "minimum_case_count", "minimum_unique_gold_case_count"},
            "sample_requirements",
        )
        required_strata = requirements.get("required_strata")
        if not isinstance(required_strata, list) or not required_strata:
            raise ValueError("sample_requirements.required_strata must be a non-empty array.")
        if any(not isinstance(label, str) or label not in STRATA for label in required_strata):
            raise ValueError("sample_requirements.required_strata contains an invalid stratum.")
        if len(set(required_strata)) != len(required_strata):
            raise ValueError("sample_requirements.required_strata must not contain duplicates.")
        for field in ("minimum_case_count", "minimum_unique_gold_case_count"):
            value = requirements.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"sample_requirements.{field} must be a positive integer.")
    decision_requirements = data.get("decision_requirements")
    if decision_requirements is not None:
        if not isinstance(decision_requirements, dict):
            raise ValueError("decision_requirements must be an object.")
        fields = {
            "system", "max_false_accept_rate_upper_95pct",
            "max_false_reject_rate_upper_95pct", "minimum_coverage",
            "maximum_review_routed_rate", "maximum_median_review_seconds",
            "minimum_review_time_measurement_coverage",
        }
        _reject_extra_fields(decision_requirements, fields, "decision_requirements")
        if decision_requirements.get("system") not in SYSTEMS:
            raise ValueError("decision_requirements.system must be baseline or dss.")
        for field in (
            "max_false_accept_rate_upper_95pct",
            "max_false_reject_rate_upper_95pct",
            "minimum_coverage",
            "maximum_review_routed_rate",
            "minimum_review_time_measurement_coverage",
        ):
            value = decision_requirements.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"decision_requirements.{field} must be a finite number between 0 and 1.")
        value = decision_requirements.get("maximum_median_review_seconds")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("decision_requirements.maximum_median_review_seconds must be a finite non-negative number.")
    primary_endpoint = data.get("primary_endpoint")
    if primary_endpoint is not None:
        if not isinstance(primary_endpoint, dict):
            raise ValueError("primary_endpoint must be an object.")
        _reject_extra_fields(
            primary_endpoint,
            {"outcome_class", "expected_direction", "analysis_population", "alpha",
             "registration_reference", "frozen_before_outcomes_review"},
            "primary_endpoint",
        )
        if primary_endpoint.get("outcome_class") not in OUTCOME_CLASSES:
            raise ValueError("primary_endpoint.outcome_class must be a declared outcome class.")
        if primary_endpoint.get("expected_direction") not in {"LOWER", "HIGHER"}:
            raise ValueError("primary_endpoint.expected_direction must be LOWER or HIGHER.")
        if primary_endpoint.get("analysis_population") != "ALL_PAIRED_CASES":
            raise ValueError("primary_endpoint.analysis_population must be ALL_PAIRED_CASES.")
        alpha = primary_endpoint.get("alpha")
        if isinstance(alpha, bool) or not isinstance(alpha, (int, float)) or not math.isfinite(alpha) or not 0 < alpha < 1:
            raise ValueError("primary_endpoint.alpha must be a finite number strictly between 0 and 1.")
        reference = primary_endpoint.get("registration_reference")
        if not isinstance(reference, str) or not reference.strip():
            raise ValueError("primary_endpoint.registration_reference must be a non-empty string.")
        if primary_endpoint.get("frozen_before_outcomes_review") is not True:
            raise ValueError("primary_endpoint.frozen_before_outcomes_review must be true.")
    seen = set()
    for index, case in enumerate(data["cases"]):
        prefix = f"cases[{index}]"
        if not isinstance(case, dict):
            raise ValueError(f"{prefix} must be an object.")
        _reject_extra_fields(
            case,
            {"case_id", "gold_candidate_id", "baseline", "dss", "stratum"},
            prefix,
        )
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"{prefix}.case_id must be a non-empty string.")
        if case_id in seen:
            raise ValueError(f"Duplicate case_id: {case_id}")
        seen.add(case_id)
        stratum = case.get("stratum", "UNSPECIFIED")
        if not isinstance(stratum, str) or (stratum not in STRATA and stratum != "UNSPECIFIED"):
            allowed = ", ".join(sorted(STRATA))
            raise ValueError(f"{prefix}.stratum must be one of: {allowed}.")
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


def _exact_mcnemar_p_value(baseline_only, dss_only):
    """Two-sided exact McNemar p-value conditional on discordant pairs."""
    discordant = baseline_only + dss_only
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, k) for k in range(min(baseline_only, dss_only) + 1))
    return min(1.0, 2.0 * tail / (2 ** discordant))


def _binomial_cdf(k, n, probability):
    """Stable binomial lower-tail probability for exact interval inversion."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if probability <= 0.0:
        return 1.0
    if probability >= 1.0:
        return 0.0
    log_p = math.log(probability)
    log_q = math.log1p(-probability)
    logs = [
        math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
        + i * log_p + (n - i) * log_q
        for i in range(k + 1)
    ]
    peak = max(logs)
    return min(1.0, math.exp(peak) * math.fsum(math.exp(value - peak) for value in logs))


def _clopper_pearson(successes, total, confidence=0.975):
    """Two-sided exact binomial interval; confidence must be in (0, 1)."""
    if total == 0:
        return [0.0, 1.0]
    if not 0 <= successes <= total:
        raise ValueError("successes must be between zero and total")
    tail = (1.0 - confidence) / 2.0

    def bisect(target, increasing):
        low, high = 0.0, 1.0
        for _ in range(64):
            mid = (low + high) / 2.0
            value = _binomial_cdf(successes if increasing else successes - 1, total, mid)
            # A binomial lower-tail probability decreases monotonically with p.
            if value > target:
                low = mid
            else:
                high = mid
        return (low + high) / 2.0

    lower = 0.0 if successes == 0 else bisect(1.0 - tail, False)
    upper = 1.0 if successes == total else bisect(tail, True)
    return [lower, upper]


def _paired_prevalence_difference_interval(baseline_only, dss_only, total, alpha=0.05):
    """Conservative paired risk-difference interval with >=1-alpha coverage via Bonferroni CP."""
    if total == 0:
        return None
    discordant = baseline_only + dss_only
    component_confidence = 1.0 - alpha / 2.0
    discordance_interval = _clopper_pearson(discordant, total, confidence=component_confidence)
    direction_interval = _clopper_pearson(dss_only, discordant, confidence=component_confidence)
    direction_bounds = [
        2.0 * direction_interval[0] - 1.0,
        2.0 * direction_interval[1] - 1.0,
    ]
    products = [
        discordance_interval[0] * direction_bounds[0],
        discordance_interval[0] * direction_bounds[1],
        discordance_interval[1] * direction_bounds[0],
        discordance_interval[1] * direction_bounds[1],
    ]
    return [max(-1.0, min(products)), min(1.0, max(products))]


def _paired_class_comparisons(matrix):
    """One-versus-rest paired comparisons for each mutually exclusive outcome."""
    total = sum(sum(row.values()) for row in matrix.values())
    comparisons = {}
    for outcome in OUTCOME_CLASSES:
        baseline_only = sum(
            matrix[baseline][dss]
            for baseline in OUTCOME_CLASSES if baseline == outcome
            for dss in OUTCOME_CLASSES if dss != outcome
        )
        dss_only = sum(
            matrix[baseline][dss]
            for baseline in OUTCOME_CLASSES if baseline != outcome
            for dss in OUTCOME_CLASSES if dss == outcome
        )
        both = matrix[outcome][outcome]
        neither = total - baseline_only - dss_only - both
        comparisons[outcome] = {
            "case_count": total,
            "baseline_and_dss": both,
            "baseline_only": baseline_only,
            "dss_only": dss_only,
            "neither": neither,
            "discordant_case_count": baseline_only + dss_only,
            "prevalence_difference_dss_minus_baseline": (
                (dss_only - baseline_only) / total if total else None
            ),
            "prevalence_difference_confidence_interval_95pct": (
                _paired_prevalence_difference_interval(baseline_only, dss_only, total)
            ),
            "exact_mcnemar_p_value_two_sided": _exact_mcnemar_p_value(
                baseline_only, dss_only
            ),
        }
    ordered = sorted(
        ((name, item["exact_mcnemar_p_value_two_sided"]) for name, item in comparisons.items()),
        key=lambda pair: pair[1],
    )
    previous_adjusted = 0.0
    family_size = len(ordered)
    for rank, (name, p_value) in enumerate(ordered):
        adjusted = min(1.0, (family_size - rank) * p_value)
        previous_adjusted = max(previous_adjusted, adjusted)
        comparisons[name]["holm_adjusted_p_value_within_four_outcome_family"] = previous_adjusted
    return {
        "outcomes": comparisons,
        "interpretation": (
            "Each outcome is compared one-versus-rest on the same paired cases. "
            "Exact two-sided McNemar p-values are shown unadjusted and with Holm "
            "family-wise adjustment across the four outcome classes in this group. "
            "The four outcome tests are dependent. Adjustments are not combined "
            "across strata. Results are exploratory, not a pilot gate or proof "
            "of causal superiority."
        ),
    }


def _primary_endpoint_spec_sha256(endpoint):
    """Fingerprint only the scientific endpoint specification, not its audit pointer."""
    specification = {
        key: endpoint[key]
        for key in ("outcome_class", "expected_direction", "analysis_population", "alpha")
    }
    canonical = json.dumps(
        specification, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _primary_endpoint_assessment(data, matrix):
    endpoint = data.get("primary_endpoint")
    if endpoint is None:
        return {
            "status": "NOT_CONFIGURED",
            "endpoint": None,
            "interpretation": "No primary endpoint was declared in the evaluation input.",
        }
    outcome = endpoint["outcome_class"]
    comparison = _paired_class_comparisons(matrix)["outcomes"][outcome]
    alpha = endpoint["alpha"]
    interval = _paired_prevalence_difference_interval(
        comparison["baseline_only"], comparison["dss_only"],
        comparison["case_count"], alpha=alpha,
    )
    estimate = comparison["prevalence_difference_dss_minus_baseline"]
    if interval is None:
        status = "INDETERMINATE"
    elif endpoint["expected_direction"] == "LOWER":
        status = (
            "SUPPORTS_DIRECTION" if interval[1] < 0 else
            "OPPOSITE_DIRECTION" if interval[0] > 0 else "INDETERMINATE"
        )
    else:
        status = (
            "SUPPORTS_DIRECTION" if interval[0] > 0 else
            "OPPOSITE_DIRECTION" if interval[1] < 0 else "INDETERMINATE"
        )
    p_value = comparison["exact_mcnemar_p_value_two_sided"]
    return {
        "status": status,
        "endpoint": {
            "outcome_class": outcome,
            "expected_direction": endpoint["expected_direction"],
            "analysis_population": endpoint["analysis_population"],
            "alpha": alpha,
            "registration_reference": endpoint["registration_reference"],
            "endpoint_spec_sha256": _primary_endpoint_spec_sha256(endpoint),
            "frozen_before_outcomes_review_attested": True,
            "case_count": comparison["case_count"],
            "prevalence_difference_dss_minus_baseline": estimate,
            "prevalence_difference_confidence_interval": interval,
            "exact_mcnemar_p_value_two_sided": p_value,
            "two_sided_mcnemar_p_value_at_or_below_alpha": p_value <= alpha,
        },
        "interpretation": (
            "Direction status is based on the pre-specified confidence interval for the "
            "marginal one-versus-rest prevalence difference (dss minus baseline). "
            "The McNemar p-value is reported separately and is not substituted for the "
            "interval decision. The registration reference and frozen-before-review "
            "flag are submitter attestations; timing and provenance are not independently verified."
        ),
    }


def _stratum_metrics(cases):
    grouped = {}
    for case in cases:
        label = case.get("stratum", "UNSPECIFIED")
        grouped.setdefault(label, []).append(case)
    results = {}
    for label, group in sorted(grouped.items()):
        matrix = _paired_outcome_matrix(group)
        results[label] = {
            "case_count": len(group),
            "systems": {system: _system_metrics(group, system) for system in SYSTEMS},
            "paired_outcome_matrix": matrix,
            "paired_class_comparisons": _paired_class_comparisons(matrix),
        }
    return results


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


def _sample_sufficiency(data, cases):
    requirements = data.get("sample_requirements")
    if requirements is None:
        return {
            "status": "NOT_CONFIGURED",
            "requirements": None,
            "strata": {},
            "interpretation": "No sample-count gate was pre-registered in the input.",
        }
    unclassified_case_count = sum(
        case.get("stratum", "UNSPECIFIED") == "UNSPECIFIED" for case in cases
    )
    observed_strata = {
        case.get("stratum", "UNSPECIFIED") for case in cases
        if case.get("stratum", "UNSPECIFIED") != "UNSPECIFIED"
    }
    unassessed_strata = sorted(observed_strata - set(requirements["required_strata"]))
    results = {}
    for label in requirements["required_strata"]:
        group = [case for case in cases if case.get("stratum", "UNSPECIFIED") == label]
        case_count = len(group)
        unique_gold_count = sum(case["gold_candidate_id"] is not None for case in group)
        missing = case_count == 0
        below_minimum = (
            case_count < requirements["minimum_case_count"]
            or unique_gold_count < requirements["minimum_unique_gold_case_count"]
        )
        status = "MISSING" if missing else ("BELOW_MINIMUM" if below_minimum else "SUFFICIENT")
        results[label] = {
            "status": status,
            "case_count": case_count,
            "unique_gold_case_count": unique_gold_count,
            "minimum_case_count": requirements["minimum_case_count"],
            "minimum_unique_gold_case_count": requirements["minimum_unique_gold_case_count"],
        }
    overall = (
        "SUFFICIENT"
        if unclassified_case_count == 0 and not unassessed_strata and all(item["status"] == "SUFFICIENT" for item in results.values())
        else "INSUFFICIENT"
    )
    return {
        "status": overall,
        "unclassified_case_count": unclassified_case_count,
        "unassessed_strata": unassessed_strata,
        "requirements": {
            "required_strata": list(requirements["required_strata"]),
            "minimum_case_count": requirements["minimum_case_count"],
            "minimum_unique_gold_case_count": requirements["minimum_unique_gold_case_count"],
        },
        "strata": results,
        "interpretation": (
            "Count screening only: meeting these minima does not establish representative sampling, "
            "statistical power, precision, or field performance."
        ),
    }


def _decision_assessment(data, systems):
    requirements = data.get("decision_requirements")
    if requirements is None:
        return {
            "status": "NOT_CONFIGURED",
            "system": None,
            "criteria": {},
            "interpretation": "No operational decision thresholds were pre-registered in the input.",
        }
    system = requirements["system"]
    metrics = systems[system]
    criteria = {}

    def assess(name, observed, comparator, threshold, unavailable=False, not_applicable=False):
        if not_applicable:
            status = "NOT_APPLICABLE"
        elif unavailable:
            status = "INDETERMINATE"
        elif observed is None:
            status = "INDETERMINATE"
        elif comparator == "<=":
            status = "PASS" if observed <= threshold else "FAIL"
        else:
            status = "PASS" if observed >= threshold else "FAIL"
        criteria[name] = {
            "status": status,
            "observed": observed,
            "comparator": comparator,
            "threshold": threshold,
        }

    false_accept_interval = metrics["false_accept_rate_95pct_wilson"]
    assess(
        "false_accept_rate_upper_95pct",
        false_accept_interval[1] if false_accept_interval is not None else None,
        "<=", requirements["max_false_accept_rate_upper_95pct"],
    )
    false_reject_interval = metrics["false_reject_rate_95pct_wilson"]
    assess(
        "false_reject_rate_upper_95pct",
        false_reject_interval[1] if false_reject_interval is not None else None,
        "<=", requirements["max_false_reject_rate_upper_95pct"],
    )
    assess("coverage", metrics["coverage"], ">=", requirements["minimum_coverage"])
    assess(
        "review_routed_rate",
        metrics["review_routed_cases"] / metrics["cases"] if metrics["cases"] else None,
        "<=", requirements["maximum_review_routed_rate"],
    )
    no_review = metrics["review_routed_cases"] == 0
    assess(
        "median_review_seconds",
        metrics["median_review_seconds"],
        "<=", requirements["maximum_median_review_seconds"],
        unavailable=not no_review and metrics["median_review_seconds"] is None,
        not_applicable=no_review,
    )
    assess(
        "review_time_measurement_coverage",
        metrics["review_time_measurement_coverage"],
        ">=", requirements["minimum_review_time_measurement_coverage"],
        not_applicable=no_review,
    )
    statuses = [item["status"] for item in criteria.values() if item["status"] != "NOT_APPLICABLE"]
    overall = "FAIL" if "FAIL" in statuses else (
        "INDETERMINATE" if "INDETERMINATE" in statuses else "PASS"
    )
    return {
        "status": overall,
        "system": system,
        "criteria": criteria,
        "interpretation": (
            "Threshold screening only. Error criteria use the upper endpoint of the reported 95% Wilson interval. "
            "PASS does not establish representative sampling, causal superiority, statistical power, or field performance."
        ),
    }


def _pilot_readiness(sample_sufficiency, decision_assessment):
    sample_status = sample_sufficiency["status"]
    decision_status = decision_assessment["status"]
    statuses = (sample_status, decision_status)
    if all(status == "NOT_CONFIGURED" for status in statuses):
        overall = "NOT_CONFIGURED"
    elif "INSUFFICIENT" in statuses or "FAIL" in statuses:
        overall = "FAIL"
    elif any(status in {"NOT_CONFIGURED", "INDETERMINATE"} for status in statuses):
        overall = "INDETERMINATE"
    else:
        overall = "PASS"
    return {
        "status": overall,
        "sample_sufficiency_status": sample_status,
        "decision_assessment_status": decision_status,
        "interpretation": (
            "This combines only the configured count-screening and operational-threshold gates. "
            "PASS is not full pilot approval and does not establish representative sampling, "
            "statistical power, legal compliance or field performance."
        ),
    }


def evaluate(data):
    _validate(data)
    cases = data["cases"]
    system_results = {system: _system_metrics(cases, system) for system in SYSTEMS}
    paired_matrix = _paired_outcome_matrix(cases)
    sample_sufficiency = _sample_sufficiency(data, cases)
    decision_assessment = _decision_assessment(data, system_results)
    primary_endpoint_assessment = _primary_endpoint_assessment(data, paired_matrix)
    return {
        "report_version": "paired-pilot-metrics/2.1",
        "dataset_id": data.get("dataset_id"),
        "dataset_version": data.get("dataset_version"),
        "case_count": len(cases),
        "systems": system_results,
        "paired_case_count": len(cases),
        "paired_outcome_matrix": paired_matrix,
        "paired_class_comparisons": _paired_class_comparisons(paired_matrix),
        "stratum_metrics": _stratum_metrics(cases),
        "sample_sufficiency": sample_sufficiency,
        "decision_assessment": decision_assessment,
        "primary_endpoint_assessment": primary_endpoint_assessment,
        "pilot_readiness": _pilot_readiness(sample_sufficiency, decision_assessment),
        "method_notes": [
            "A decision is automatically accepted when terminal_state is VERIFIED or CORRECTED.",
            "A false accept is any automatic acceptance whose selected candidate differs from the gold candidate, including cases labelled with no unique answer.",
            "False-accept rate denominator is all automatic acceptances; prevalence denominator is all cases.",
            "A false reject is an unresolved decision on a case with a non-null unique gold candidate; its rate denominator is all cases with a unique gold label.",
            "A correct abstention is an unresolved decision on a case whose gold candidate is null; false-reject prevalence uses all cases as its denominator.",
            "The paired outcome matrix places each case once at the intersection of its baseline and dss outcome classes, exposing case-level trade-offs without treating the systems as independent samples.",
            "paired_class_comparisons reports one-versus-rest paired discordances, prevalence differences, conservative paired 95% confidence intervals and exact two-sided McNemar p-values with Holm adjustment across the four outcomes within each comparison group; intervals use two 97.5% exact Clopper-Pearson component intervals with Bonferroni coverage, assume independent case pairs, and are exploratory rather than a pilot gate or proof of causal superiority. Clustered or repeated entities require a cluster-aware method not implemented here.",
            "Stratum metrics repeat the same paired measures within each declared case stratum; omitted stratum labels are grouped explicitly as UNSPECIFIED, never silently assigned to a fault class.",
            "Stratum rates are descriptive and retain their raw denominators; small or synthetic strata do not establish statistical significance or field performance.",
            "The optional sample_sufficiency gate checks pre-registered raw-case and unique-gold counts for required strata, fails closed for UNSPECIFIED cases or observed strata omitted from the requirements, and does not establish representative sampling, statistical power, precision or field performance.",
            "The optional decision_assessment compares pre-registered operational thresholds with observed metrics; false-accept and false-reject criteria use upper 95% Wilson bounds, and missing denominators or review-time evidence are indeterminate rather than passes.",
            "The optional primary_endpoint_assessment reports the pre-declared one-versus-rest outcome, direction, all-paired-case population, alpha, conservative confidence interval and exact McNemar p-value. It does not alter pilot readiness; registration reference and timing are submitter attestations, not independently verified.",
            "pilot_readiness combines only the configured sample-sufficiency and operational-threshold gates; it is not full pilot approval or evidence of representative field performance.",
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
