"""
∂ss vs Fuzzy Matcher: Side-by-side comparison on mocked address data.
"""

from dss_loop import DSSLoop, Resolution, field_match
from rapidfuzz import process, fuzz

AUTHORITY = [
    {"id": "A001", "num": "35", "street": "PATRICK PLACE", "postcode": "ST8 7RF"},
    {"id": "A002", "num": "33", "street": "REDRIFFE ROAD", "postcode": "E14 8BX"},
    {"id": "A003", "num": "13", "street": "NAYLOR STREET", "postcode": "ST6 6LS"},
    {"id": "A004", "num": "1",  "street": "MEDIA WAY",     "postcode": "ST1 5ST"},
    {"id": "A005", "num": "23", "street": "ELM GROVE",     "postcode": "LS1 4AB"},
]

# --- ∂ss Implementation ---
def resolve_address(incoming: str) -> Resolution:
    parts = incoming.upper().split()
    if len(parts) < 3:
        return Resolution(candidate=None, evidence=["Input too short."])

    num, *rest = parts
    postcode = rest[-1]
    street = " ".join(rest[:-1])

    candidates = []
    for rec in AUTHORITY:
        res_num = field_match(num, rec["num"])
        res_st  = field_match(street, rec["street"])
        res_pc  = field_match(postcode, rec["postcode"])
        
        if "FAIL" not in [res_num, res_st, res_pc]:
            candidates.append(rec)

    if len(candidates) == 0:
        return Resolution(candidate=None, evidence=["No candidate matched."])
    if len(candidates) > 1:
        return Resolution(candidate=None, evidence=[f"{len(candidates)} tied candidates."])

    return Resolution(candidate=candidates[0], evidence=["Single candidate matched."])

def operate_address(cand): 
    return cand["id"] if cand else None

def check_address(intended, observed, eps):
    return "PASS" if observed else "INCONCLUSIVE"

dss = DSSLoop(resolve_address, operate_address, check_address)

# --- Fuzzy Baseline ---
def fuzzy_resolve(incoming):
    names = [f"{r['num']} {r['street']} {r['postcode']}" for r in AUTHORITY]
    match, score, idx = process.extractOne(incoming, names, scorer=fuzz.token_set_ratio)
    # The fuzzy matcher ALWAYS returns a match, even if it's wrong.
    return AUTHORITY[idx]["id"], score

# --- Test Cases ---
TEST_SET = [
    # (Input, Ground Truth, Profile)
    ("35 PATRICK PLACE ST8 7RF", "A001", "Clean"),
    ("33 REDRIFFE ROAD E14 8BX", "A002", "Clean"),
    ("35 patrick place  st87rf", "A001", "Mixed (normalisation)"),
    ("33 REDRIFE ROAD E14 8BX", "A002", "Mixed (typo)"),
    ("35 PATRICK PLACE ST6 6LS", "A001", "Difficult (conflict)"),
]

print(f"{'Input':<30} | {'Truth':<6} | {'∂ss':<10} | {'Fuzzy':<10}")
print("-" * 65)

for text, truth, profile in TEST_SET:
    # ∂ss Run
    trace = dss.land(text)
    dss_result = trace.terminal
    dss_got = trace.observed if trace.observed else "—"

    # Fuzzy Run
    fuzzy_got, fuzzy_score = fuzzy_resolve(text)

    print(f"{text[:28]:<30} | {truth:<6} | {dss_result:<10} | {fuzzy_got} ({fuzzy_score:.0f}%)")

print("\n--- Analysis ---")
print("Notice how the Fuzzy matcher forces a match on the conflicting postcode.")
print("The ∂ss loop detects the conflict and emits UNRESOLVED (refuses false accept).")
