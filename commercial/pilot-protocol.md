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
python -m unittest discover -s tests -p 'test_comparison.py' -v
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

## Executable paired pilot metrics

A paired pilot must score both systems against the same gold label for every
case. The repository includes a metadata-only evaluator:

```bash
python experiments/pilot_metrics.py path/to/paired-pilot.json --json-out pilot-report.json
python -m unittest discover -s tests -v
```

The input is a JSON object with non-empty dataset_id and dataset_version strings and a cases array; both provenance fields are mandatory. The versioned [JSON Schema](../experiments/schemas/paired-pilot-input-v1.schema.json) publishes the machine-readable input contract, while the evaluator performs its own runtime validation.
Each case has a unique pseudonymous case_id, an explicitly present gold_candidate_id
(candidate ID or null when no unique answer exists), and baseline/dss decision
objects. A missing gold_candidate_id is invalid; it is never inferred to mean
that the case is ambiguous.
Each decision contains terminal_state (VERIFIED, CORRECTED or UNRESOLVED),
selected_candidate_id (null only when unresolved), trace_complete (boolean),
and a required review_routed boolean, plus optional non-negative latency_ms and
review_seconds. Only unresolved cases may be routed to review, and a review time
requires review_routed=true. The report separates routed-case count from review-time
measurement coverage. Do not include raw addresses or customer identifiers.

The evaluator rejects duplicate case IDs, invalid states, accepted decisions
without a candidate, unresolved decisions with a selected candidate, malformed
trace flags and invalid measurements. Runtime validation also rejects undeclared
fields at the dataset, case and decision levels, matching the schema's
`additionalProperties: false` boundary; whitespace-only provenance identifiers
are rejected as well. This prevents unrecognised address/customer fields from
being silently accepted as part of the metadata-only input contract. Both systems
are scored over the same paired cases. A wrong candidate or any acceptance where the gold label is null
counts as a false accept. An unresolved decision against a non-null gold
candidate is a false reject; an unresolved decision where the gold candidate
is null is a correct abstention. The evaluator reports these separately so
abstention cannot conceal a refusal of a case with a known unique answer.

The JSON report gives raw counts and explicit denominators for false-accept
rate and prevalence, false-reject rate and prevalence, correct abstentions,
correct auto-resolution, coverage, unresolved rate, correction precision,
trace completeness, review time and latency. False-accept and false-reject
rates each include a 95% Wilson score interval. False-reject rate uses only
cases with a non-null unique gold label as its denominator; false-reject
prevalence uses all paired cases. When there are no uniquely labelled cases,
the false-reject rate and interval are null. Latency p95 uses the
nearest-rank definition. Missing latency/review measurements are counted
separately rather than imputed. An empty acceptance denominator yields null,
not a misleading zero rate.

A fully synthetic paired fixture exercises the command-line path, including
writing a report file:

```bash
python experiments/pilot_metrics.py experiments/fixtures/paired-pilot-synthetic-v1.json --json-out pilot-report.json
```

The fixture contains four pseudonymous cases: a correct verification, a
baseline false acceptance against a known label, a correct ∂ss correction,
and an ambiguous case with no unique gold candidate. It also includes two
explicit human-review routes with measured review time. The fixture is a
plumbing and metric-definition check only; its deliberately small outcomes
are not evidence of comparative real-world performance. The unit suite runs
this CLI fixture and checks that stdout and the written JSON report agree.

The evaluator does not decide whether a pilot passes. Risk thresholds, minimum
coverage, acceptable review burden, dataset strata, label adjudication and
confidence requirements must be agreed before opening the held-out set.
This is a report calculator, not a customer-data store or an address matcher.
