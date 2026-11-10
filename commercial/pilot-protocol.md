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


## Pilot ground-truth and pre-registration gate

Do not score a held-out pilot until its identity labels and evaluation rules are
fixed. A defensible protocol should record the following before either system
is run against the held-out cases:

1. **Identity unit:** define what one gold candidate represents (for example,
   a delivery point, premise or customer-authorised destination). Do not let
   the meaning vary between cases.
2. **Authority and snapshot:** name the lawful source of truth, its version or
   snapshot date, the authority hierarchy for conflicting records and the
   permitted evidence for deciding identity.
3. **Adjudication:** have two reviewers label cases independently against the
   declared evidence; send disagreements to a named adjudication process and
   retain the reason for the final label. A null `gold_candidate_id` means
   adjudicators have concluded that no unique answer exists. It must not mean
   missing, unavailable or unfinished labelling; exclude unadjudicated cases
   from the scored set rather than converting them to null.
4. **Separation:** freeze the gold labels before scoring. Keep any mapping from
   pseudonymous case IDs to source records outside this repository, under the
   data controller's access and retention rules. Neither system should receive
   the gold labels as decision inputs.
5. **Paired execution:** run baseline and ∂ss on the same case set and declared
   input fields. Record software/ruleset versions, configuration, thresholds
   and run dates; do not tune against the held-out labels.
6. **Sampling plan:** predeclare the population, inclusion/exclusion rules,
   sample size and relevant strata (such as exact, formatting-only, typo,
   duplicate, conflicting, incomplete and stale records). Report each stratum
   separately where the sample supports it.
7. **Decision costs:** agree the operational consequences and relative costs
   of false acceptance, false rejection, correct abstention and human review.
   Set minimum coverage, maximum error rates, review burden and confidence
   requirements before opening the held-out results.

The synthetic fixture does not satisfy these requirements. It tests metric
plumbing and definitions only; it is not a substitute for an adjudicated,
representative pilot dataset.

The evaluator does not decide whether a pilot passes. Risk thresholds, minimum
coverage, acceptable review burden, dataset strata, label adjudication and
confidence requirements must be agreed before opening the held-out set.

The `paired_outcome_matrix` is a four-by-four transition table: rows classify
the baseline decision and columns classify the ∂ss decision as correct automatic
resolution, false accept, false reject or correct abstention. Every paired case
appears in exactly one cell. This exposes case-level trade-offs—for example, a
baseline false accept becoming a ∂ss false reject—rather than hiding them inside
separate aggregate rates. The report format is `paired-pilot-metrics/1.7`; version 1.4 introduced sample-sufficiency screening, version 1.5 added fail-closed unclassified-case handling, version 1.6 reports observed strata omitted from pre-registration, and version 1.7 adds optional operational threshold assessment. The report also groups the
same measures by case stratum. Accepted labels are `EXACT`, `FORMATTING_ONLY`,
`TYPO`, `DUPLICATE`, `CONFLICTING`, `INCOMPLETE` and `STALE`. The input
field is optional for compatibility; omitted labels are explicitly reported as
`UNSPECIFIED`, not silently assigned to a disturbance class. Unknown or
non-string labels are rejected. Each case receives one primary stratum; where
several disturbances coexist, the primary-classification rule must be declared
before scoring and secondary disturbances must not be silently discarded from
the underlying study record. The labels mean: EXACT (no material input
disturbance), FORMATTING_ONLY (presentation changes only), TYPO (textual
mutation), DUPLICATE (multiple records or candidates representing a duplicate
condition), CONFLICTING (contradictory identity evidence), INCOMPLETE (required
identity evidence absent) and STALE (record freshness or version is out of
date). These are study classifications, not automatic conclusions made by the
evaluator. Each stratum includes its case count, both
systems' metrics and its own paired outcome matrix, so denominators remain
visible within the subgroup. Stratum rates are descriptive; small sample sizes
and synthetic fixtures do not establish statistical significance or field
performance. Pre-register the classification rules and sampling plan before
held-out scoring.

This is a report calculator, not a customer-data store or an address matcher.

## Pre-registered sample-sufficiency screening

The paired metrics input may optionally include `sample_requirements` before
held-out scoring. It declares the required primary strata, a minimum raw case
count per stratum and a separate minimum count of cases with a non-null unique
gold label. The evaluator reports each required stratum as `MISSING`,
`BELOW_MINIMUM` or `SUFFICIENT`, and the overall gate as
`INSUFFICIENT` unless every required stratum meets both minima. If no
requirements are supplied, the report says `NOT_CONFIGURED`; it does not
invent thresholds or infer them from observed results.

Example:

```json
{
  "sample_requirements": {
    "required_strata": ["EXACT", "TYPO", "DUPLICATE"],
    "minimum_case_count": 100,
    "minimum_unique_gold_case_count": 80
  }
}
```

These example numbers are illustrative, not recommended universal thresholds.
The actual strata and minima must be justified and frozen in the study's
pre-registration before held-out labels are opened. The unique-gold count is
separate because false-reject rates use only cases with a unique gold answer.
A stratum with no cases is reported as `MISSING`; a present stratum that fails
either count is `BELOW_MINIMUM`.

This is a count-screening gate only. Passing it does not establish that the
sampling frame or selection method is representative, that observations are
independent, or that the study has adequate statistical power or precision.
Those require a defensible population definition, sampling method and
study-specific statistical design. The gate must never be described as a
representativeness or significance test.

Where sample requirements are configured, the gate also counts cases labelled
`UNSPECIFIED`. Any unclassified case forces the overall status to
`INSUFFICIENT`, even if every required stratum meets its count minima. This
prevents a partially classified dataset from appearing to pass merely because
the explicitly named strata are large enough. The evaluator still permits
omitted strata when no sample gate is configured, preserving the earlier
descriptive-report behaviour.
The gate also lists any observed, classified strata that were not named in
`required_strata` as `unassessed_strata`. Their presence forces the overall
gate to `INSUFFICIENT`; a pre-registration cannot silently omit a category
that appears in the scored data. Include every intended stratum in the
pre-registered list, or revise the study design before opening held-out
results. This is an accounting safeguard, not a claim that all strata have
been sampled representatively.
## Pre-registered operational threshold assessment

The optional `decision_requirements` input records the system under assessment
(`baseline` or `dss`) and the operational limits agreed before held-out
evaluation: maximum upper 95% Wilson bound for false-accept rate, maximum
upper 95% Wilson bound for false-reject rate, minimum coverage, maximum
human-review routing rate, maximum median measured review time, and minimum
review-time measurement coverage. All six limits are explicit numeric inputs;
the evaluator does not supply universal defaults.

The report emits one criterion per limit with its observed value, comparator,
threshold and `PASS`, `FAIL` or `INDETERMINATE` status. The aggregate status is
`FAIL` if any criterion fails; otherwise it is `INDETERMINATE` if any required
measurement is unavailable; it is `PASS` only when every criterion passes.
False-accept and false-reject limits are tested against the **upper endpoint**
of their 95% Wilson intervals, not the point estimate. Thus a small sample
cannot pass an error ceiling merely because its observed error rate is low.

The review-routing rate is routed cases divided by all paired cases; median review time is calculated from supplied review-duration observations, and measurement coverage is timed routed cases divided by all routed cases. A known low measurement-coverage fraction is a `FAIL` against a higher minimum; an absent median when reviews were routed is `INDETERMINATE`.

If there are no automatic acceptances or no uniquely labelled cases, the
corresponding error criterion is `INDETERMINATE` because its denominator is
absent. If review is routed but review-time measurements are absent, the
review-time criteria are `INDETERMINATE`. When no cases are routed to review,
median review time and measurement coverage are marked not applicable and do
not block the other criteria; the review-routing rate remains measurable.

This is an auditable threshold comparison, not a complete pilot pass
certificate. `PASS` means only that the supplied pre-registered numerical
limits were met on the evaluated cases. It does not prove representativeness,
independence, statistical power, causal superiority, legal compliance or
field performance. The sample-sufficiency screen and study-design review
remain separate gates. Thresholds must be frozen before held-out labels or
results are examined.
