# ∂ss Address Resolution Loop

A strict control loop for resolving noisy, incomplete, or conflicting address and identity records.

This is not a fuzzy matcher. It is a verification envelope. It refuses to guess. If the evidence does not support a single confident landing, it returns `UNRESOLVED`.

## The Core Problem

In high-stakes environments (logistics, healthcare, finance, AI guardrails), a **false accept** (wrong destination accepted with high confidence) is infinitely more expensive than an **unresolved case** (left open for human review).

Most systems force a match and bolt a confidence score on the end. This method treats false accepts as a critical error class and leaves the case open when evidence is conflicting.

## The Five-Step Loop

1. **Intended Address (I):** State the exact destination or outcome required.
2. **Resolution:** Apply evidence. Select a single candidate, or emit `UNRESOLVED`.
3. **Operation:** Execute only if a candidate is selected.
4. **Return Check (∂ss):** Compare intended vs. observed under a declared tolerance (ε). If they do not match, the landing is refused.
5. **Terminal State:** `VERIFIED` | `CORRECTED` | `UNRESOLVED`.

**Governing Principle:** The forward operation must meet the return check. An unresolved outcome is a valid and preferred terminal state when evidence does not support a confident landing.

## Why "UNRESOLVED" is First-Class

- The system must not invent certainty to force a landing.
- False acceptance is treated as a critical error, not an acceptable trade-off.
- Every decision, including refusals, is logged with the evidence used and the rule that produced the outcome.

## Quick Start

1. Install dependencies:
   ```bash
   pip install rapidfuzz
