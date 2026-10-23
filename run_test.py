"""
∂ss vs Fuzzy Matcher (Fair Comparison) - Final Audited Version
"""

from dss_loop import (
    DSSLoop, Resolution, field_match, 
    resolve_address, operate_address, check_address, 
    normalise, levenshtein
)
from rapidfuzz import process, fuzz

# Instantiate the DSS Loop
dss = DSSLoop(resolve_address, operate_address, check_address)

# --- Fuzzy Baseline with Threshold ---
def fuzzy_resolve(incoming, threshold=80):
    from dss_loop import AUTHORITY
    names = [f"{r['num']} {r['street']} {r['postcode']}" for r in AUTHORITY]
    match, score, idx = process.extractOne(incoming, names, scorer=fuzz.token_set_ratio)
    if score < threshold:
        return None, score
    return AUTHORITY[idx]["id"], score

# --- Test Bench ---
# (incoming_text, ground_truth_id, expected_system_response, profile)
TEST_SET = [
    ("35 PATRICK PLACE ST8 7RF", "A001", "VERIFIED", "Clean"),
    ("33 REDRIFFE ROAD E14 8BX", "A002", "VERIFIED", "Clean"),
    ("35 patrick place st87rf",  "A001", "CORRECTED", "Mixed (normalisation)"),
    ("33 REDRIFE ROAD E14 8BX",  "A002", "CORRECTED", "Mixed (typo)"),
    ("35 PATRICK PLACE ST6 6LS", "A001", "UNRESOLVED", "Difficult (conflict)"),
    ("99 UNKNOWN STREET ZZ9 9ZZ", "A006", "UNRESOLVED", "No match"),
]

print(f"{'Input':<30} | {'Truth':<6} | {'Expected':<12} | {'∂ss Result':<12} | {'Fuzzy Result':<15}")
print("-" * 85)

metrics = {
    "dss_verified": 0, "dss_corrected": 0, "dss_unresolved": 0, "dss_fa": 0,
    "fuzzy_resolved": 0, "fuzzy_unresolved": 0, "fuzzy_fa": 0,
}

for text, truth, expected, profile in TEST_SET:
    # ∂ss Run
    trace = dss.land(truth, text)
    
    # Check for FA (Observed doesn't match Ground Truth)
    if trace.observed is not None and trace.observed != truth:
        metrics["dss_fa"] += 1
        dss_display = f"FA! ({trace.observed})"
    else:
        dss_display = trace.terminal
        if trace.terminal == "VERIFIED": metrics["dss_verified"] += 1
        elif trace.terminal == "CORRECTED": metrics["dss_corrected"] += 1
        elif trace.terminal == "UNRESOLVED": metrics["dss_unresolved"] += 1

    # Fuzzy Run
    fuzzy_got, fuzzy_score = fuzzy_resolve(text)
    if fuzzy_got is None:
        fuzzy_display = f"UNRESOLVED ({fuzzy_score:.0f}%)"
        metrics["fuzzy_unresolved"] += 1
    else:
        if fuzzy_got != truth:
            fuzzy_display = f"FA! ({fuzzy_got})"
            metrics["fuzzy_fa"] += 1
        else:
            fuzzy_display = f"{fuzzy_got} ({fuzzy_score:.0f}%)"
            metrics["fuzzy_resolved"] += 1

    print(f"{text[:28]:<30} | {truth:<6} | {expected:<12} | {dss_display:<12} | {fuzzy_display:<15}")

print("\n" + "=" * 60)
print("BENCHMARK SUMMARY")
print("=" * 60)
print(f"{'Metric':<25} | {'∂ss':<10} | {'Fuzzy':<10}")
print("-" * 50)
print(f"{'Correct Matches (Verified)':<25} | {metrics['dss_verified']:<10} | {metrics['fuzzy_resolved']:<10}")
print(f"{'Corrected Matches':<25} | {metrics['dss_corrected']:<10} | {'N/A':<10}")
print(f"{'Abstentions (Unresolved)':<25} | {metrics['dss_unresolved']:<10} | {metrics['fuzzy_unresolved']:<10}")
print(f"{'FALSE ACCEPTS':<25} | {metrics['dss_fa']:<10} | {metrics['fuzzy_fa']:<10}")
print("=" * 60)
