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
    resolution: Resolution
    observed: Optional[Any] = None
    check: Optional[CheckResult] = None
    terminal: Optional[Terminal] = None
    rule: str = ""

class DSSLoop:
    def __init__(self, resolve_fn, operate_fn, check_fn, epsilon: float = 0.0):
        """
        resolve_fn: (I) -> Resolution
        operate_fn: (candidate) -> observed
        check_fn: (I, observed, epsilon) -> CheckResult
        """
        self.resolve_fn = resolve_fn
        self.operate_fn = operate_fn
        self.check_fn = check_fn
        self.epsilon = epsilon

    def land(self, intended: Any) -> Trace:
        # Step 2: Resolution
        resolution = self.resolve_fn(intended)
        trace = Trace(intended=intended, resolution=resolution)

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
            trace.terminal = "VERIFIED"
            trace.rule = "Forward operation met return check."
        elif trace.check == "FAIL":
            trace.terminal = "UNRESOLVED"
            trace.rule = "Return check failed — refused to land."
        else:
            trace.terminal = "UNRESOLVED"
            trace.rule = "Return check inconclusive."

        return trace

# --- Helper functions for the address domain ---

def normalise(s: str) -> str:
    s = s.upper().strip()
    s = re.sub(r"\s+", " ", s)
    return s

def field_match(a: str, b: str) -> CheckResult:
    a, b = normalise(a), normalise(b)
    if a == b:
        return "PASS"
    # single-character transposition is recoverable
    if len(a) == len(b) and sum(1 for x, y in zip(a, b) if x != y) == 1:
        return "CORRECTED"
    return "FAIL"
