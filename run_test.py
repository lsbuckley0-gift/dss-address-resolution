"""
∂ss vs Fuzzy Matcher (Fair Comparison) - Repaired Version
"""

from dss_loop import DSSLoop, Resolution, field_match, resolve_address, operate_address, check_address
from rapidfuzz import process, fuzz

# Instantiate the DSS Loop using the functions from dss_loop.py
dss = DSSLoop(resolve_address, operate_address, check_address)

# --- Fuzzy Baseline with Threshold ---
def fuzzy_resolve(incoming, threshold=80):
    from dss_loop import AUTHORITY # Import the authority list
    names = [f"{r['num']} {r['street']} {r['postcode']}" for r in AUTHORITY]
    match, score, idx = process.extractOne(incoming, names, scorer=fuzz.token_set_ratio)
    if score < threshold:
        return None, score
    return AUTHORITY[idx]["id"], score

# --- Test Bench ---
# (input, ground_truth, expected_system_response, profile)
TEST_SET = [
    ("35 PATRICK PLACE ST8 7RF", "A001", "VERIFIED", "Clean"),
    ("33 REDRIFFE ROAD E14 8BX", "A002", "VERIFIED", "Clean"),
    ("35 patrick place st87rf",  "A001", "VERIFIED", "Mixed (normalisation)"),
    ("33 REDRIFE ROAD E14 8BX",  "A002", "CORRECTED", "Mixed (typo)"),
    ("35 PATRICK PLACE ST6 6LS", "A001", "UNRESOLVED", "Difficult (conflict)"),
]

print(f"{'Input':<30} | {'Truth':<6} | {'Expected':<12} | {'∂ss':<10} | {'Fuzzy':<10}")
print("-" * 80)

dss_fa = 0
fuzzy_fa = 0

for text, truth, expected, profile in TEST_SET:
    trace = dss.land(text)
    dss_result = trace.observed if trace.observed else "—"

    if dss_result != "—" and dss_result != truth:
        dss_fa += 1

    fuzzy_got, fuzzy_score = fuzzy_resolve(text)
    fuzzy_result = fuzzy_got if fuzzy_got else "—"
    if fuzzy_result != "—" and fuzzy_result != truth:
        fuzzy_fa += 1

    print(f"{text[:28]:<30} | {truth:<6} | {expected:<12} | {trace.terminal:<10} | {fuzzy_result} ({fuzzy_score:.0f}%)")

print("\n--- False Accepts ---")
print(f"∂ss loop: {dss_fa}")
print(f"Fuzzy matcher: {fuzzy_fa}")
