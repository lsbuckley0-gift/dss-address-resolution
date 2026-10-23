"""
∂ss Address Resolution Loop - Core Engine
The governing principle: the forward operation must meet the return check.
An unresolved outcome is a valid and preferred terminal state.
"""

from dataclasses import dataclass, field
from typing import Optional, Any, Literal
import re

Terminal = Literal["VERIFIED", "CORRECTED", "UNRESOLVED"]
CheckResult = Literal["PASS", "FAIL", "INCONCLUSIVE"]

@dataclass
class Resolution:
    candidate: Optional[Any] = None
    evidence: list = field(default_factory=list)

@dataclass
class Trace:
    intended: Any
    incoming: Any
    resolution: Resolution
    observed: Optional[Any] = None
    check: Optional[CheckResult] = None
    terminal: Optional[Terminal] = None
    rule: str = ""

class DSSLoop:
    def __init__(self, resolve_fn, operate_fn, check_fn, epsilon: float = 0.0):
        self.resolve_fn = resolve_fn
        self.operate_fn = operate_fn
        self.check_fn = check_fn
        self.epsilon = epsilon

    def land(self, intended: Any, incoming: Any) -> Trace:
        # Step 2: Resolution resolves the *incoming* data
        resolution = self.resolve_fn(incoming)
        trace = Trace(intended=intended, incoming=incoming, resolution=resolution)

        if resolution.candidate is None:
            trace.terminal = "UNRESOLVED"
            trace.rule = "Resolution emitted no confident candidate."
            return trace

        # Step 3: Operation
        trace.observed = self.operate_fn(resolution.candidate)

        # Step 4: Return Check (∂ss)
        trace.check = self.check_fn(intended, trace.observed, self.epsilon)

        # Step 5: Terminal State
        if trace.check == "PASS":
            if resolution.evidence and "CORRECTED" in " ".join(resolution.evidence):
                trace.terminal = "CORRECTED"
                trace.rule = "Recoverable mismatch detected and resolved."
            else:
                trace.terminal = "VERIFIED"
                trace.rule = "Forward operation met return check."
        elif trace.check == "FAIL":
            trace.terminal = "UNRESOLVED"
            trace.rule = "Return check failed — refused false accept."
        else:
            trace.terminal = "UNRESOLVED"
            trace.rule = "Return check inconclusive."

        return trace


# --- Normalisation & Levenshtein ---

def normalise(s: str) -> str:
    s = s.upper().strip()
    s = re.sub(r"\s+", " ", s)
    # Normalise compressed postcodes: "ST87RF" -> "ST8 7RF"
    s = re.sub(r"([A-Z]{1,2}\d{1,2}[A-Z]?)(\d[A-Z]{2})$", r"\1 \2", s)
    return s

def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def field_match(a: str, b: str) -> CheckResult:
    a, b = normalise(a), normalise(b)
    if a == b:
        return "PASS"
    if levenshtein(a, b) == 1:
        return "CORRECTED"
    return "FAIL"


# --- Address Domain Helpers ---

AUTHORITY = [
    {"id": "A001", "num": "35", "street": "PATRICK PLACE", "postcode": "ST8 7RF"},
    {"id": "A002", "num": "33", "street": "REDRIFFE ROAD", "postcode": "E14 8BX"},
    {"id": "A003", "num": "13", "street": "NAYLOR STREET", "postcode": "ST6 6LS"},
    {"id": "A004", "num": "1",  "street": "MEDIA WAY",     "postcode": "ST1 5ST"},
    {"id": "A005", "num": "23", "street": "ELM GROVE",     "postcode": "LS1 4AB"},
]

def resolve_address(incoming: str) -> Resolution:
    parts = normalise(incoming).split()
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
            candidates.append((rec, [res_num, res_st, res_pc]))

    if len(candidates) == 0:
        return Resolution(candidate=None, evidence=["No candidate matched."])
    if len(candidates) > 1:
        return Resolution(candidate=None, evidence=[f"{len(candidates)} tied candidates."])

    rec, matches = candidates[0]
    evidence = [f"num={matches[0]}, street={matches[1]}, postcode={matches[2]}"]
    return Resolution(candidate=rec, evidence=evidence)

def operate_address(cand):
    return cand["id"] if cand else None

def check_address(intended, observed, eps):
    if observed is None:
        return "INCONCLUSIVE"
    return "PASS" if observed == intended else "FAIL"
