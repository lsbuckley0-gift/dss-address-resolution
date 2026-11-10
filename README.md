# ∂ss Address Resolution Loop

A strict control loop for resolving noisy, incomplete, or conflicting address and identity records.

∂ss is designed as a verification envelope around candidate generation. It distinguishes a plausible candidate from an established resolution. If the evidence does not support a safe, unique landing, the outcome is `UNRESOLVED`.

## The Core Problem

Address workflows encounter incomplete, mistyped, stale, duplicated and conflicting records. A textually similar candidate is not automatically the intended destination.

An unsafe acceptance can propagate into fulfilment, customer records and downstream systems. The relative cost of a false acceptance and a human-reviewed unresolved case depends on the organisation and use case; it should be measured in each deployment rather than assumed universally.

## The Five-Step Loop

1. **Intended Address (I):** Preserve the exact intended destination and its provenance.
2. **Resolution:** Evaluate candidates and their evidence; permit no candidate or multiple candidates.
3. **Operation:** Apply only an authorised, recorded transformation.
4. **Return Check (∂ss):** Compare the observed result against the original intention using declared, field-aware rules.
5. **Terminal State:** `VERIFIED` | `CORRECTED` | `UNRESOLVED`.

**Governing principle:** the forward operation must satisfy the return check. An unresolved outcome is valid when evidence does not support a confident landing.

## Why UNRESOLVED Is First-Class

- Similarity is evidence, not proof of destination identity.
- Conflicting or ambiguous cases must not be forced into an automatic match.
- Decisions, including refusals, should retain the evidence, rule and reason that produced the outcome.
- Human review remains an explicit route where automation cannot safely decide.

## Quick Start

The synthetic demonstration has no third-party dependencies and uses fictional records only.

```bash
python demo/dss_demo.py
python demo/dss_demo.py --json-out demo-trace.json
python -m unittest discover -s tests -v
```

See [the demonstration guide](demo/README.md) for its scope and limitations.

A separate [synthetic vehicle-event collision benchmark](experiments/README.md) tests identity preservation across parcel-event sequences.

## Core Loop Checks

The original `dss_loop.py` resolver treats a normalised UK postcode as its
outward and inward code together. The final two whitespace-separated tokens
are parsed as the postcode; preceding tokens are the premise and street.
Direct unit tests cover exact verification, one-edit street and postcode
correction, compressed postcode normalisation, rejection when a valid candidate
belongs to a different intended identity, conflicting postcodes, failed and
inconclusive return checks, and the rule that a missing candidate skips
operation and return check.

Run the dependency-free core tests with:
`python -m unittest discover -s tests -v`.

## Legacy Fuzzy Comparison Harness

The optional `run_test.py` comparison uses RapidFuzz as its baseline. Install
its pinned dependency and run:

```bash
python -m pip install -r requirements-comparison.txt
python -m unittest tests.test_comparison -v
python run_test.py
```

The comparison applies the same `dss_loop.normalise` function to incoming
text and authority-record strings before fuzzy scoring. Its policy is explicit:
`token_set_ratio`, a score threshold of 80, and abstention when the highest
score is tied. This avoids granting the baseline an arbitrary first-record
decision in an ambiguous tie. The ∂ss harness separately asserts every declared
terminal outcome, fixture accounting, and zero false accepts.

These are synthetic fixtures, not a representative accuracy study. Threshold
selection, tie policy and normalisation must be fixed before evaluation on a
representative labelled dataset; results should not be generalised from this
small comparison.

## Commercial and Evaluation Documents

- [Commercial market position](commercial/market-position.md)
- [Pilot and evaluation protocol](commercial/pilot-protocol.md)
- [Reproducible demonstration specification](commercial/demo-spec.md)

## Important Scope

The included demonstration is a small reference implementation of the decision discipline. It is not a production address matcher, does not use live or licensed address data, and does not establish accuracy or superiority over existing services.

Production use requires representative, lawfully obtained and labelled data; agreed identity rules; security and privacy review; integration testing; and an evaluation against the customer's current baseline. Do not upload personal address data or licensed PAF data to this public repository.

## Status

The repository describes the method and contains a synthetic demonstration with automated tests. Customer performance, operational readiness and commercial value remain to be established through a controlled pilot.
