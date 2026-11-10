"""
∂ss vs fuzzy baseline comparison.

Both systems receive the same canonical text normalisation. The fuzzy baseline
uses a declared score threshold and abstains on an equal-best candidate tie.
"""

from dss_loop import (
    DSSLoop, resolve_address, operate_address, check_address, normalise, AUTHORITY
)
from rapidfuzz import process, fuzz


def fuzzy_resolve(incoming, threshold=80, authority=None):
    """Return (record_id, score); abstain below threshold or on a best-score tie."""
    records = AUTHORITY if authority is None else authority
    if not records:
        return None, 0.0

    # Apply the same canonical text normalisation used by the ∂ss resolver.
    names = [
        normalise(f"{record['num']} {record['street']} {record['postcode']}")
        for record in records
    ]
    query = normalise(incoming)
    ranked = process.extract(query, names, scorer=fuzz.token_set_ratio, limit=None)
    if not ranked:
        return None, 0.0

    best_score = ranked[0][1]
    if best_score < threshold:
        return None, best_score

    best = [item for item in ranked if item[1] == best_score]
    if len(best) != 1:
        return None, best_score

    _, score, index = best[0]
    return records[index]["id"], score


TEST_SET = [
    ("35 PATRICK PLACE ST8 7RF", "A001", "VERIFIED", "Clean"),
    ("33 REDRIFFE ROAD E14 8BX", "A002", "VERIFIED", "Clean"),
    ("35 patrick place st87rf",  "A001", "VERIFIED", "Mixed (normalisation)"),
    ("33 REDRIFE ROAD E14 8BX",  "A002", "CORRECTED", "Mixed (typo)"),
    ("35 PATRICK PLACE ST6 6LS", "A001", "UNRESOLVED", "Difficult (conflict)"),
    ("99 UNKNOWN STREET ZZ9 9ZZ", "A006", "UNRESOLVED", "No match"),
]


def main():
    dss = DSSLoop(resolve_address, operate_address, check_address)
    print(f"{'Input':<30} | {'Truth':<6} | {'Expected':<12} | {'∂ss Result':<12} | {'Fuzzy Result':<15}")
    print("-" * 85)

    metrics = {
        "dss_verified": 0, "dss_corrected": 0, "dss_unresolved": 0, "dss_fa": 0,
        "fuzzy_resolved": 0, "fuzzy_unresolved": 0, "fuzzy_fa": 0,
    }

    for incoming, truth, expected, profile in TEST_SET:
        trace = dss.land(truth, incoming)
        assert trace.terminal == expected, (
            f"∂ss expectation mismatch for {incoming!r}: "
            f"expected {expected}, got {trace.terminal}"
        )

        if trace.observed is not None and trace.observed != truth:
            metrics["dss_fa"] += 1
            dss_display = f"FA! ({trace.observed})"
        else:
            dss_display = trace.terminal
            if trace.terminal == "VERIFIED":
                metrics["dss_verified"] += 1
            elif trace.terminal == "CORRECTED":
                metrics["dss_corrected"] += 1
            elif trace.terminal == "UNRESOLVED":
                metrics["dss_unresolved"] += 1

        fuzzy_got, fuzzy_score = fuzzy_resolve(incoming)
        if fuzzy_got is None:
            fuzzy_display = f"UNRESOLVED ({fuzzy_score:.0f}%)"
            metrics["fuzzy_unresolved"] += 1
        elif fuzzy_got != truth:
            fuzzy_display = f"FA! ({fuzzy_got})"
            metrics["fuzzy_fa"] += 1
        else:
            fuzzy_display = f"{fuzzy_got} ({fuzzy_score:.0f}%)"
            metrics["fuzzy_resolved"] += 1

        print(f"{incoming[:28]:<30} | {truth:<6} | {expected:<12} | {dss_display:<12} | {fuzzy_display:<15}")

    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)
    assert (
        metrics["dss_verified"] + metrics["dss_corrected"] +
        metrics["dss_unresolved"] + metrics["dss_fa"]
    ) == len(TEST_SET)
    assert metrics["dss_fa"] == 0, "∂ss produced a false accept in the comparison fixture set"
    print(f"{'Metric':<25} | {'∂ss':<10} | {'Fuzzy':<10}")
    print("-" * 50)
    print(f"{'Correct Matches (Verified)':<25} | {metrics['dss_verified']:<10} | {metrics['fuzzy_resolved']:<10}")
    print(f"{'Corrected Matches':<25} | {metrics['dss_corrected']:<10} | {'N/A':<10}")
    print(f"{'Abstentions (Unresolved)':<25} | {metrics['dss_unresolved']:<10} | {metrics['fuzzy_unresolved']:<10}")
    print(f"{'FALSE ACCEPTS':<25} | {metrics['dss_fa']:<10} | {metrics['fuzzy_fa']:<10}")
    print("=" * 60)


if __name__ == "__main__":
    main()
