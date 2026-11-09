"""Shared evidence classification for ∂ss decision traces.

Classification describes evidence quality; it does not choose a terminal state.
Domain evaluators remain responsible for deciding VERIFIED/CORRECTED/UNRESOLVED.
"""

def classify_evidence(*, missing=False, conflicting=False, ambiguous=False):
    """Return the shared evidence class for a set of observed conditions."""
    if missing and conflicting:
        return "MIXED"
    if missing:
        return "INSUFFICIENT"
    if ambiguous:
        return "AMBIGUOUS"
    if conflicting:
        return "CONFLICTING"
    return "SUFFICIENT_AND_CONSISTENT"
