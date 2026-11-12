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
separate aggregate rates. The report format is `paired-pilot-metrics/1.9`; version 1.4 introduced sample-sufficiency screening, version 1.5 added fail-closed unclassified-case handling, version 1.6 reports observed strata omitted from pre-registration, version 1.7 adds operational threshold assessment, version 1.8 combines the configured gates into a pilot-readiness status, version 1.9 adds paired one-versus-rest outcome comparisons, and version 2.0 adds conservative paired prevalence-difference confidence intervals. The report also groups the
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

## Combined pilot-readiness status

The report-level `pilot_readiness` combines the optional sample-sufficiency
and operational-threshold assessments without conflating their meanings:

- `PASS`: both gates are configured and pass.
- `FAIL`: either configured gate fails.
- `INDETERMINATE`: no configured gate fails, but at least one is missing or
  indeterminate.
- `NOT_CONFIGURED`: neither gate was supplied.

This prevents a passing operational-threshold assessment from being mistaken
for a complete readiness result when sample requirements were never set. It
also prevents a sufficient sample count from concealing a breached operational
limit. The combined status covers only these two configured gates; it is not
full pilot approval and cannot establish representativeness, statistical
power, legal compliance or real-world performance.


## Paired outcome comparisons

Alongside the four-by-four paired outcome matrix, report version 1.9 emits
`paired_class_comparisons` for each outcome class, both overall and within
each observed stratum. Each class is treated as a binary one-versus-rest
endpoint on the same paired cases. The report gives the number of cases in
which both systems produced that class, baseline only, ∂ss only, or neither;
the discordant-pair count; and the marginal prevalence difference
(∂ss minus baseline).

For each class, the report also provides a conservative 95% confidence
interval for the paired prevalence difference (∂ss minus baseline). Let
q be the probability that the systems disagree on the one-versus-rest
classification, and let θ be the conditional probability that only ∂ss has
the outcome among discordant pairs. The marginal difference is
q × (2θ − 1). The implementation constructs two-sided 97.5% exact
Clopper-Pearson intervals for q and θ, then combines their endpoint products.
Bonferroni's inequality gives at least 95% simultaneous coverage for the two
components, and the resulting interval is conservative for the paired
prevalence difference under independent, identically distributed case pairs.
When no discordances are observed, the interval remains wide rather than
mistaking an observed zero difference for certainty. This is not a
case-resampling interval and does not account for clustering.

For each class, the report calculates a two-sided exact McNemar p-value
from the discordant pairs, then applies the Holm procedure across the four
outcome-class tests within that overall or stratum-specific comparison group.
Both unadjusted and Holm-adjusted values are reported. This is a paired test of
equal marginal proportions for that one-versus-rest endpoint; it does not
treat baseline and ∂ss as independent samples. When there are no discordant
pairs, the exact p-value is 1.0. The direction and size of the observed
prevalence difference remain visible regardless of the p-value.

The four outcome classes are mutually exclusive, so their one-versus-rest
tests are dependent. Holm adjustment controls the family-wise error rate
across the four tests within each reported comparison group under arbitrary
dependence, but the overall and separate stratum families are not adjusted
together. The results remain exploratory and must not be read as four
independent confirmations or as an automatic superiority decision. The exact
McNemar calculation also assumes independent case pairs. If multiple rows
belong to the same address, household, route, customer or other shared unit,
the independence assumption may fail; a cluster-aware paired method is needed,
and this report does not implement one.
A confirmatory study must pre-register one primary endpoint (or a defensible
multiplicity procedure), its direction, analysis population and handling of
strata before held-out outcomes are examined. Stratum-level comparisons are
also reported separately so an aggregate change does not conceal a subgroup
trade-off. Small strata can produce highly discrete p-values and weak evidence;
no inference should be made from a synthetic fixture.

This analysis describes paired outcome changes in the evaluated cases. It
does not establish causation, representativeness, operational utility, or
field performance, and it does not alter the existing pilot-readiness gates.

The paired confidence interval is an uncertainty interval for the marginal
one-versus-rest prevalence difference, not for the false-accept or
false-reject conditional rates used by the operational decision gate. Those
existing gates continue to use their separately specified upper Wilson bounds.
The interval is emitted for every outcome class and comparison group; it is
descriptive and does not automatically pass or fail pilot readiness.


## Pre-registered primary endpoint (report version 2.1)

The optional `primary_endpoint` input declares exactly one primary outcome
class, the expected direction of change, the analysis population, two-sided
alpha, a registration reference, and a submitter attestation that the endpoint
was frozen before outcomes review. The supported population in this version is
`ALL_PAIRED_CASES`; the marginal prevalence difference is always ∂ss minus
baseline on that complete paired denominator. This prevents a post hoc choice
of a favourable subset or denominator within this report contract.

The report's `primary_endpoint_assessment` gives the pre-declared endpoint's
prevalence difference, a conservative confidence interval with at least
1-alpha coverage (two-sided exact Clopper-Pearson component intervals combined
using Bonferroni), and the two-sided exact McNemar p-value. The direction status
is based on whether the confidence interval excludes zero in the declared
direction: `SUPPORTS_DIRECTION`, `OPPOSITE_DIRECTION`, or
`INDETERMINATE`. The p-value and its comparison with alpha are reported
separately; neither is silently substituted for the other.

This assessment is deliberately not folded into `pilot_readiness` and does
not override the existing sample or operational gates. A missing declaration
is reported as `NOT_CONFIGURED`. The registration reference and
`frozen_before_outcomes_review` value are submitter attestations only: this
tool does not independently verify the timestamp, registration record,
analysis-population lock, or whether anyone had access to held-out outcomes.
A reference string is an audit pointer, not proof of pre-registration.

The report also emits `endpoint_spec_sha256`, a deterministic SHA-256
fingerprint of the four scientific design fields (outcome class, expected
direction, analysis population and alpha). The fingerprint is independent of
JSON key ordering and excludes the registration pointer and attestation. It
allows an evaluator to compare the analysed specification with a separately
archived pre-registration record. The digest establishes content identity only;
it does not establish when the record was created or whether it was concealed
from analysts. Chronology still requires a trusted external timestamp or
registration archive.

## Registration evidence verifier (v1)

`experiments/registration_evidence.py` provides an offline comparison between
a declared primary endpoint and a separate registration evidence record. The
record schema is
`experiments/schemas/registration-evidence-v1.schema.json`. It binds the
registration reference to the endpoint's SHA-256 specification fingerprint,
and requires `registration_event_id` plus
`registration_event_evidence_reference` as explicit join keys to the first
`REGISTRATION_FROZEN` event in the audit chain. The record, event ID,
claimed timestamp and evidence reference must agree. It records three distinct
claimed events:

1. `registered_at_utc`: when the frozen endpoint record was registered;
2. `outcomes_accessed_at_utc`: when held-out outcomes were first accessed;
3. `analysis_started_at_utc`: when analysis began.

The verifier rejects missing or undeclared fields, malformed/non-UTC
timestamps, timestamps with more than six fractional-second digits, and
malformed digests. The six-digit limit matches Python datetime precision and
the audit-event chain; accepting finer precision would silently truncate it
during parsing and could make distinct instants compare equal. It reports
whether the reference and scientific-specification digest match, whether the
claimed registration time precedes outcome access, and whether analysis began
strictly after that access. Equal recorded timestamps are not ordered.

**Critical boundary:** these are chronology claims, not authenticated facts.
The verifier always emits
`timestamp_verification: NOT_INDEPENDENTLY_VERIFIED`. A timestamp-shaped
string and an evidence reference do not authenticate a trusted timestamp
authority, prove that the record existed at that time, establish who could
read the outcomes, or prove that the access log is append-only. Those require
independent timestamp/signature and access-control evidence, which this
offline verifier does not implement. Do not upgrade its result to
`VERIFIED`.

This separation protects the study from a circular audit: reading the held-out
outcomes is itself an event that must be recorded, not an invisible step that
can be retrospectively moved to suit the result. The registration record must
be preserved independently before outcome access; the outcome-access event
must be recorded independently of the analysis report. A later report may
compare those records, but must not rewrite them.

Run the comparison with separate JSON files:

```bash
python -m experiments.registration_evidence paired-pilot.json registration-evidence.json
```

The pilot input must contain its `primary_endpoint`; the second file must
conform to the registration-evidence schema. Exit code `0` means the digest,
reference and *claimed* event order are internally consistent; it does not
mean the timestamp is trusted. Exit code `1` means an integrity or claimed
chronology check failed. Exit code `2` means the files or record are invalid.

The registration record's `registration_event_id` and
`registration_event_evidence_reference` allow a direct cross-check against
the event chain. The Python API
`verify_registration_chain_binding(endpoint, registration_record, events)`
combines the endpoint fingerprint check with the hash-chain check and confirms
that the record names the chain's first registration event, carries the same
claimed timestamp, and names the same event evidence reference. It also cross-checks the
registration record's claimed first outcome-access and analysis-start times
against the first `OUTCOME_ACCESS` and sole `ANALYSIS_STARTED` events in
the chain. A mismatch in any of these bindings fails. A matching join does not
authenticate the timestamps or event sources; it establishes only that the
supplied records agree on the recorded event identities, claimed times and
registration evidence pointer.

## Hash-linked audit event chain (v1)

`experiments/audit_event_chain.py` supplies a deterministic SHA-256
event-chain implementation. Each event binds its sequence number, event ID,
event type, UTC timestamp, pseudonymous actor reference, evidence reference,
previous event digest and its own digest. The canonical hash input is compact,
sorted-key UTF-8 JSON with the event's own `event_sha256` field omitted.
The first event links to a fixed all-zero genesis digest; every later event
links to the immediately preceding event digest.

The required lifecycle is:

1. `REGISTRATION_FROZEN` — exactly once, and first;
2. `OUTCOME_ACCESS` — at least once after registration; repeat this event
   for every subsequent access, including accesses after analysis begins;
3. `ANALYSIS_STARTED` — exactly once, after the first outcome access.

Event timestamps must be strictly increasing at microsecond precision.
Equal timestamps are rejected rather than arbitrarily ordered. The verifier
also rejects duplicate event IDs, non-contiguous sequence numbers, unsupported
fields, invalid UTC timestamps, incorrect previous hashes and content-digest
mismatches. `append_audit_event` validates the existing prefix before
returning a new event list; it does not persist or rewrite the record.

Verify a retained event-chain JSON file without modifying it:

```bash
python -m experiments.audit_event_chain events.json
```

Exit code `0` means the supplied prefix is internally consistent and contains
the required lifecycle events; `1` means a valid but incomplete prefix; `2`
means the file or chain is invalid. The JSON Schema is
`experiments/schemas/audit-event-chain-v1.schema.json`. The schema
validates individual record shapes; the Python verifier enforces cross-event
ordering and hash links.

**Integrity boundary:** `VALID_PREFIX` means only that the supplied
records link and hash correctly. It is not proof of truth, trusted time,
identity, or immutable storage. A party able to rewrite the entire chain can
recalculate its hashes. A deleted suffix cannot be detected from the shortened
file alone. To make later rewriting or truncation detectable, an independently
controlled system must retain and timestamp the chain-head digest at intervals
(or anchor each event), and the verifier must compare the supplied chain with
that independent anchor. That external anchor is not implemented here and is
always reported as `NOT_VERIFIED`. The event references must resolve to
evidence held under appropriate access controls; the hash chain does not
authenticate those references or the actors who supplied them.

This is tamper evidence for a retained sequence, not tamper-proof storage.
Preserve the original event source separately; do not treat a regenerated
chain as an independent witness to its own history.

### Comparing an external checkpoint

`verify_external_checkpoint` compares the retained event chain with a separate
checkpoint record conforming to
`experiments/schemas/audit-chain-checkpoint-v1.schema.json`. The checkpoint
binds the registration event ID, a sequence number and the digest at that
sequence to an anchor reference and claimed UTC anchor time. It may point to
an earlier event while the local chain contains later events. If the retained
chain ends before the checkpoint sequence, the comparison reports a mismatch;
if the digest or registration identity differs, it also reports a mismatch.

Supply the record to the read-only verifier with:

```bash
python -m experiments.audit_event_chain events.json --checkpoint checkpoint.json
```

A matching checkpoint means the supplied chain contains the same event digest
at the declared sequence and registration identity. The timestamp comparison
only checks that the claimed anchor time is not earlier than the event time.
The result always says `anchor_authentication: NOT_VERIFIED`: the verifier
does not validate a signature, trusted timestamp token, authority identity or
independent storage. A checkpoint only protects the prefix up to its sequence;
later truncation requires a later independently retained checkpoint. This is
the comparison interface for external anchoring, not an anchoring service.

For multiple independently retained checkpoints, supply an ordered array
conforming to `experiments/schemas/audit-chain-checkpoint-series-v1.schema.json`:

```bash
python -m experiments.audit_event_chain events.json --checkpoints checkpoints.json \
  --checkpoint-minimum-sequence 12
```

The series verifier requires strictly increasing event sequence numbers,
strictly increasing claimed anchor times and distinct anchor references.
Every checkpoint must bind to the same registration event and to the digest
at its declared sequence. Reordered or replayed checkpoints, duplicate anchor
references, non-increasing anchor times and digest mismatches produce a series
mismatch. Event-sequence gaps are permitted: checkpoint sequence identifies an
event index, not a requirement to anchor every event. The verifier therefore
checks the order and bindings of the checkpoints actually supplied; it does
not establish that intermediate checkpoints were never omitted, that this is
the latest series, or that an operator's retained history cannot be rolled
back. A caller may supply `minimum_sequence` to the API or
`--checkpoint-minimum-sequence` to the CLI. The newest supplied checkpoint
must be at or beyond that non-negative event-sequence floor; otherwise the
series reports `rollback_floor: BELOW_FLOOR` and fails. Equality is accepted.
When no floor is supplied, the result says `rollback_floor: NOT_SUPPLIED`.
This detects a stale presented series only relative to the floor the operator
provides; it cannot prove that the floor itself is genuine.

The floor must be retained independently of the checkpoint files, updated
atomically with the operator's acceptance record, and protected against
rollback. If that state is unavailable or cannot be authenticated, the
verifier cannot infer a safe floor from the presented checkpoint list. This
is an operator-supplied precondition, not durable state managed by this
library. The verifier still cannot authenticate the authority behind
any entry.


## Explicit audit trust-store preflight (v1)

`experiments/trust_store.py` validates a caller-supplied allowlist of Ed25519
public keys before a future signature-verification stage. The strict schema is
`experiments/schemas/audit-trust-store-v1.schema.json`. Each key entry requires
a unique key ID, a named authority, a 32-byte base64 public key, explicit
permitted purposes, a half-open UTC validity interval, an ACTIVE/REVOKED/DISABLED
status and a reference describing the asserted trust basis.

The API `validate_trust_store(store)` rejects undeclared fields, duplicate
IDs, unsupported algorithms, malformed keys and invalid validity intervals.
`resolve_eligible_key(store, key_id=..., purpose=..., at_utc=...)` fails closed
for unknown, inactive, out-of-purpose or out-of-validity keys. An empty
allowlist is valid configuration but makes no key eligible.

**Trust boundary:** these functions do not verify a signature, authenticate an
authority, validate the trust-basis reference, or prove the supplied time.
The allowlist is caller-supplied policy; putting a public key in it does not
make that key independently trustworthy. The synthetic test key is not an
operational key and no real authority is configured. Outputs deliberately say
`NOT_PERFORMED` and `NOT_ESTABLISHED`; they must not be represented as
authenticated evidence. A subsequent stage must verify a detached signature
over a canonical checkpoint payload and separately establish the provenance
and governance of the trust-store source.


## Detached Ed25519 checkpoint signatures (v1)

`experiments/checkpoint_signature.py` verifies a detached Ed25519 signature
over a domain-separated canonical JSON representation of the complete
checkpoint record. The signature envelope is defined by
`experiments/schemas/audit-chain-checkpoint-signature-v1.schema.json`.
Canonicalisation uses sorted object keys, compact separators and UTF-8, with
the fixed domain prefix `∂ss-audit-checkpoint-signature/v1` followed by a
newline. The signature therefore binds the checkpoint's registration event,
sequence, event digest, claimed anchor time and anchor reference together.

`verify_signed_checkpoint(events, checkpoint, signature_envelope, trust_store,
at_utc=...)` first checks the checkpoint against the retained chain, then
resolves the key under the explicit trust-store purpose, status and validity
policy, and finally verifies the 64-byte Ed25519 signature. Unknown, revoked,
disabled, out-of-purpose and out-of-validity keys do not reach signature
verification. A modified checkpoint payload invalidates its detached signature.

The pinned verification dependency is recorded in
`requirements-audit-crypto.txt`. Tests generate ephemeral keys and synthetic
checkpoint data; no private key or operational authority is committed.

**Authentication boundary:** `signature_verification: VALID` means the
private key corresponding to the configured public key signed these exact
canonical bytes. It does not establish who controls that key, whether the
trust-store itself came from an independently governed source, whether the
claimed anchor time is true, or whether the underlying event happened. The
combined result can be `MATCH` while authority and timestamp authentication
remain explicitly `NOT_ESTABLISHED`. Independent trust-store governance and
a trusted time source remain external requirements.


Verify a signed checkpoint from files without modifying any input:

```bash
python -m experiments.audit_event_chain events.json \
  --signed-checkpoint checkpoint.json \
  --signature checkpoint-signature.json \
  --trust-store audit-trust-store.json \
  --at-utc 2026-11-10T10:04:00Z
```

All four signed-checkpoint inputs are required together. The caller supplies
`--at-utc` explicitly; this is used only to evaluate the configured key's
validity interval and is not treated as trusted time. Exit code `0` requires
a complete event lifecycle, a matching checkpoint binding and a valid
signature. Exit code `1` indicates a validly parsed but incomplete or
mismatching chain/checkpoint/signature result; exit code `2` indicates
malformed files or invalid arguments. The CLI emits the component results so
a valid signature cannot conceal a failed chain binding.


## Out-of-band trust-policy digest pin (v1)

`experiments/trust_policy_pin.py` adds an independent configuration-integrity
preflight. It validates the supplied trust store, serialises the complete
record as sorted-key, compact UTF-8 JSON, and computes its SHA-256 digest.
`verify_trust_store_pin(store, pin)` compares that digest with a caller-supplied
64-character lowercase hexadecimal digest and requires a non-empty pin-source
reference.

The pin must be provisioned and retained independently of the trust store.
Changing a key, status, permitted purpose, validity interval, public key or
trust-basis reference changes the digest and returns `MISMATCH`. JSON object
key order does not change the digest; array order remains part of the canonical
record. An empty allowlist can be pinned, but still authorises no key.

**Critical boundary:** `MATCH` proves only canonical digest equality against
the supplied pin. The verifier cannot establish who issued the pin, whether
its reference is genuine, or whether its delivery channel is independent.
The output therefore states
`pin_source_authentication: NOT_INDEPENDENTLY_AUTHENTICATED` and
`trust_policy_authentication: NOT_ESTABLISHED`. Do not describe a matching
digest as proof that the named authority is genuine. The pin's provenance
must be established by an external governance process and independently
retained by the verifier operator.

This is a policy-drift detector, not a self-authenticating trust root. It
deliberately does not embed a governance public key or infer one from the
trust store it is checking.


The signed-checkpoint CLI also accepts an optional `--trust-store-pin` JSON
file with `sha256` and `source_reference` fields. When supplied, a mismatch
stops processing before public-key eligibility or signature verification and
returns `POLICY_PIN_MISMATCH`. Without the optional pin, the report explicitly
returns `trust_policy_pin: NOT_CHECKED`; signature verification remains
cryptographically meaningful only relative to the caller-supplied trust store.


## RFC 3161 trusted timestamp-token verification (v1)

`experiments/rfc3161_timestamp.py` adds a fail-closed verifier for a DER-encoded
RFC 3161 TimeStampToken (CMS ContentInfo). It is deliberately separate from the
event-chain timestamps and the Ed25519 checkpoint signature. It verifies a
timestamp over the exact caller-supplied byte sequence; callers must choose and
document the byte representation being timestamped (for example, the canonical
checkpoint payload), and must retain those bytes unchanged.

The verifier uses the OpenSSL `ts` command. It first reads the token's asserted
GMT `genTime`, then invokes timestamp verification with the exact data bytes,
an explicit caller-supplied CA PEM bundle, optional untrusted intermediates,
and `-attime` set to the token's asserted generation time. It explicitly
requires the `timestampsign` certificate purpose, supplies an isolated empty
CA path alongside the explicit CA file to prevent system CA-directory fallback,
and enables strict X.509 checks. This checks the token
signature, message imprint, TSA signing-certificate purpose (including the
critical timeStamping EKU and permitted key usage), and certificate path at the
asserted token time. The RFC 3161 command's token verification and the
certificate-purpose and time-validation options are described in the
[OpenSSL TS documentation](https://docs.openssl.org/3.4/man1/openssl-ts/) and
[OpenSSL verification options](https://docs.openssl.org/3.0/man1/openssl-verification-options/).

The caller must provide a separate pin object with exactly `sha256` and
`source_reference`. The digest covers the exact trust-anchor PEM bytes,
including line endings and whitespace. A pin mismatch prevents all OpenSSL
verification. The optional intermediate bundle is untrusted chain-building
material; it is not promoted to a trust anchor. The accepted input is a DER
TimeStampToken, not a TimeStampResp wrapper. The current parser accepts only
whole-second GMT generation-time display values. If OpenSSL reports fractional
seconds, verification fails closed rather than rounding the claimed time for
certificate-validity evaluation; fractional-time support requires a verifier
that can preserve sub-second precision end to end.

A successful result reports `timestamp_verification: VALID` and
`message_imprint: MATCH`. This means only that OpenSSL accepted the token
signature, imprint, timestamping certificate purpose and certificate path
relative to the supplied, digest-pinned trust-anchor bytes at the token's
asserted `genTime`. The pin's source reference is descriptive, not
self-authenticating. The verifier does not authenticate the anchor's issuer,
the pin's delivery channel, the TSA's governance or operational controls, the
accuracy of the TSA's clock, or the truth of the event. The timestamp is a
cryptographically validated TSA assertion—not independent proof of event
truth. A pin match is not authority authentication.

The verifier returns non-valid states for a pin mismatch, malformed token,
failed OpenSSL verification, missing OpenSSL executable or timeout. It never
falls back to machine time or the host's default CA store. The test suite includes deterministic mocked boundary tests and end-to-end
OpenSSL tests that generate an ephemeral synthetic CA, TSA certificate and
private key in a temporary directory. Those tests exercise a real token
signature, message-imprint comparison, timestamping EKU/purpose and chain
verification, but do not establish a real TSA or operational trust anchor. No
TSA URL, private key, real certificate or authority is embedded in this repository.


### Binding trusted time to the registration checkpoint

The signed-checkpoint verifier accepts the optional RFC 3161 evidence as a
complete set: token DER, trust-anchor PEM and trust-anchor pin JSON. Optional
intermediate certificates are supplied as untrusted PEM. When these inputs are
present, the token is checked against the exact same domain-separated canonical
checkpoint bytes covered by the Ed25519 signature. A timestamp over some other
file or an unbound event-log digest is not interchangeable.

For a registration-time claim, the checkpoint must refer to event sequence
zero (the first `REGISTRATION_FROZEN` event). The verified TSA `genTime` must
be at or after that event's recorded UTC time and strictly before the first
`OUTCOME_ACCESS` event. A valid token outside that interval is cryptographically
valid evidence but fails the registration-time binding. When timestamp inputs
are supplied, the combined signed-checkpoint result requires both the Ed25519
signature and this pre-outcome timestamp binding to match. Without timestamp
inputs, the result explicitly reports `registration_timestamp_binding:
NOT_SUPPLIED`; the signature-only result retains its narrower meaning.

The CLI accepts these optional arguments only as a complete set:

```bash
python -m experiments.audit_event_chain events.json \
  --signed-checkpoint checkpoint.json \
  --signature checkpoint-signature.json \
  --trust-store audit-trust-store.json \
  --at-utc 2026-11-10T10:04:00Z \
  --timestamp-token checkpoint-timestamp-token.der \
  --timestamp-trust-anchor tsa-root.pem \
  --timestamp-trust-anchor-pin tsa-root-pin.json \
  --timestamp-intermediates tsa-intermediates.pem
```

The timestamp token must have been requested for the canonical checkpoint
payload, not for the complete JSON file with arbitrary whitespace or for a
different representation. The caller must retain the exact token, canonical
payload inputs, anchor bytes, pin and any intermediate certificates used.


## RFC 3161 trust-anchor provenance attestation (v1)

`experiments/rfc3161_anchor_provenance.py` defines a detached Ed25519
attestation over a canonical, domain-separated record. The record binds the
SHA-256 digest of the exact TSA trust-anchor PEM bytes to the declared
authority name, intended usage (`RFC3161_TSA_TRUST_ANCHOR`), policy version,
monotonic sequence, issue and expiry times, and a source reference. The
signature envelope identifies the governance key. The JSON Schema is
`experiments/schemas/rfc3161-tsa-anchor-provenance-v1.schema.json`.

Verification requires a caller-supplied governance trust store containing an
eligible Ed25519 key permitted for `RFC3161_TRUST_ANCHOR_PROVENANCE`. The
authority name in the attestation must match the authority name attached to
that eligible key. The verifier checks the exact anchor-byte digest, signature,
attestation validity interval and an operator-supplied minimum sequence.
The minimum sequence is anti-rollback state only if the operator retains it
independently; it must never be reset from the attestation being checked.
An optional trust-store digest pin detects policy drift but does not
authenticate its own source.

The attestation validity interval is half-open: `issued_at_utc <= at_utc <
expires_at_utc`. The exact issue instant is accepted; the exact expiry instant
and any earlier instant are rejected. The `at_utc` value is a caller-supplied
clock assertion, not a trusted timestamp. A deployment must define and
independently protect its clock source and record the time basis used for each
verification; this verifier does not attest to wall-clock accuracy.

The governance-key eligibility interval uses the same half-open convention:
`valid_from_utc <= at_utc < valid_until_utc`. The exact start instant is
eligible; the exact end instant and any earlier instant are not. Both checks
consume the same caller-supplied `at_utc`; neither makes that clock reading
independently trustworthy.

The anti-rollback floor is also caller-supplied state, not durable state managed
by this library. An operator deployment must retain the highest accepted
sequence per governance authority/policy scope in storage protected against
rollback, update it atomically with its acceptance record, and recover it from
an independently protected backup after loss. The floor must never be
reconstructed from an untrusted attestation file. If that state is missing,
stale or cannot be authenticated, verification must not silently initialise
the floor from the presented sequence; the operator must restore trusted state
or explicitly re-provision the trust relationship. These operational controls
are not implemented by this repository's verifier.

**Critical boundary:** `VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE` means only
that the attestation signature verifies under the eligible public key in the
supplied trust store and that the signed fields bind the supplied anchor.
`authority_authentication` deliberately remains `NOT_ESTABLISHED`. This
module does not authenticate the governance key, trust-store provenance,
named authority, source reference, certificate issuer, external revocation
state or claimed time. No governance key, real authority or operational TSA
anchor is embedded. Synthetic keys in tests are ephemeral and are not
operational trust material. The attestation verifier is a separate preflight;
it does not silently upgrade the RFC 3161 verifier's trust anchor or claim
that the attestation's governance root has been independently established.


The API `verify_rfc3161_timestamp_with_provenance(...)` composes these
stages in the safe order: it verifies the signed provenance attestation first,
and does not invoke OpenSSL timestamp verification unless that preflight
returns `VALID_RELATIVE_TO_CALLER_GOVERNANCE_STORE`. The composite result
retains `governance_authentication: NOT_ESTABLISHED` even when both stages
pass. The detached signature envelope has its own strict schema at
`experiments/schemas/rfc3161-tsa-anchor-provenance-signature-v1.schema.json`.


### Provenance-first integration with signed registration checkpoints

The Python API `verify_signed_checkpoint(...)` can opt into the provenance-first
path by supplying all four of `timestamp_anchor_attestation`,
`timestamp_anchor_signature_envelope`, `timestamp_governance_trust_store` and
`timestamp_governance_minimum_sequence`, alongside the existing complete RFC
3161 token, anchor and anchor-pin inputs. A governance trust-store pin is
optional and is supplied separately as `timestamp_governance_trust_store_pin`.
Partial provenance bundles are rejected. The operator-maintained minimum
sequence is mandatory whenever provenance is enabled; it is not inferred from
the attestation.

The checkpoint verifier then calls
`verify_rfc3161_timestamp_with_provenance(...)`: the attestation must validate
against the caller-supplied governance store before OpenSSL is invoked. The
anchor provenance attestation digest and the timestamp trust-anchor pin are
separate checks: the former binds the anchor bytes to a signed governance
record; the latter compares those same bytes with an independently supplied
SHA-256 pin. Both must match. Results expose
`timestamp_anchor_provenance` separately from `timestamp_evidence`, and
`governance_authentication` remains `NOT_ESTABLISHED`.

This is an explicit opt-in extension. Existing callers that omit the
provenance bundle retain the previous timestamp-only behaviour, and callers
that omit all timestamp inputs retain signature-only behaviour. The event-chain
CLI exposes the same opt-in bundle through these additional arguments:

```bash
python -m experiments.audit_event_chain events.json \
  --signed-checkpoint checkpoint.json \
  --signature checkpoint-signature.json \
  --trust-store audit-trust-store.json \
  --at-utc 2026-11-10T10:04:00Z \
  --timestamp-token checkpoint-timestamp-token.der \
  --timestamp-trust-anchor tsa-root.pem \
  --timestamp-trust-anchor-pin tsa-root-pin.json \
  --timestamp-anchor-attestation tsa-anchor-attestation.json \
  --timestamp-anchor-signature tsa-anchor-signature.json \
  --timestamp-governance-trust-store governance-trust-store.json \
  --timestamp-governance-minimum-sequence 4 \
  --timestamp-governance-trust-store-pin governance-trust-store-pin.json
```

The four provenance inputs (attestation, signature envelope, governance
trust store and minimum sequence) are required together; the governance
trust-store pin is optional. The CLI accepts only a non-negative integer for
the minimum sequence and rejects a negative floor during argument parsing.
Provenance inputs without the complete RFC 3161 token/anchor/pin set are
rejected. No real governance root or operational TSA material is supplied by
this integration.

### TSA certificate revocation boundary

The RFC 3161 verifier evaluates the TSA certificate path at the token's
asserted `genTime` using OpenSSL `-attime`. This is a historical
certificate-validity/path check against the caller-supplied trust anchor; it
is not a historical revocation check. The verifier accepts no CRL or OCSP
response inputs and does not request revocation checking. It therefore reports
`tsa_certificate_revocation: NOT_CHECKED` and
`historical_revocation_assurance: NOT_ESTABLISHED` for every result,
including a cryptographically valid token.

A `VALID` timestamp result must not be interpreted as proof that the TSA
signing certificate was unrevoked at `genTime`, nor as proof of its
current revocation status. Establishing historical revocation would require
separately authenticated revocation evidence, an explicit issuer/serial and
certificate-identity binding, a defined evidence-time policy, and validation
of the revocation evidence's signature, scope, freshness and applicable
validity interval. None of those controls is implemented here. CRL/OCSP
support is deferred rather than inferred from ordinary chain validation.


### RFC 3161 fractional generation-time handling

The RFC 3161 token's `genTime` may be represented with fractional seconds.
The current verifier deliberately rejects such a token rather than rounding or
truncating the asserted instant: OpenSSL's `-attime` interface accepts integer
Unix seconds, and silently discarding a fraction would weaken the precision
boundary between the signed timestamp and certificate-path validation.
The parser recognises a fractional `Time stamp` field so it can return an
explicit `INVALID_TOKEN` result explaining this limitation. Whole-second
`genTime` values continue through normal token verification. This is a
conservative interoperability limitation, not evidence that fractional
RFC 3161 timestamps are invalid under the standard. Supporting them requires
a separately reviewed method that preserves the signed instant while
performing certificate validity checks at the correct applicable precision.

## Checkpoint crash-recovery classification (v1)

`experiments/checkpoint_recovery.py` classifies the retained state after an
interruption between checkpoint-payload creation and recording its acceptance.
The acceptance receipt schema is
`experiments/schemas/audit-chain-checkpoint-acceptance-v1.schema.json`.

`classify_checkpoint_recovery(events, checkpoint, acceptance_receipt,
minimum_sequence=...)` recognises these states:

- `NO_RETAINED_STATE`: neither payload nor receipt was supplied. This cannot
  distinguish first use from loss of both copies.
- `PREPARED_NOT_ACCEPTED`: a payload exists without its receipt and
  its event-chain binding and anchor-time order are valid. It is not promoted
  to an accepted state.
- `RECEIPT_WITHOUT_PAYLOAD`: receipt exists without its payload. The payload
  is not reconstructed from the receipt.
- `CONFLICT`: the pair disagrees on sequence or canonical payload digest,
  the receipt time precedes the checkpoint time, or the checkpoint does not
  bind to the supplied event chain / claims an anchor time before its event.
  These checkpoint-binding and time-order checks also apply when the receipt
  is absent; missing acceptance evidence does not excuse an invalid payload.
- `BELOW_FLOOR`: the checkpoint sequence is below the operator-supplied
  minimum sequence.
- `CONSISTENT_UNAUTHENTICATED`: payload, receipt and supplied event chain
  agree, and any supplied floor is met.

The receipt binds the checkpoint's complete canonical JSON representation
(sorted keys, compact separators, UTF-8) by SHA-256, along with its sequence.
Its timestamp must not precede the checkpoint's claimed anchor time. The
receipt schema rejects additional fields and malformed digests.

When a payload is present without a receipt, the classifier still compares
its sequence with any supplied operator-retained minimum. The recovery state
remains `PREPARED_NOT_ACCEPTED` because the acceptance receipt is absent,
while `rollback_floor` independently reports `BELOW_FLOOR`,
`MEETS_FLOOR` or `NOT_SUPPLIED`. An incomplete write must not suppress a
known rollback warning. A receipt without its payload similarly retains its
own sequence-floor comparison but is never treated as a reconstructed
checkpoint. Its interpretation must state whether the receipt sequence is
below the supplied floor, meets it, or has no supplied floor; the state remains
`RECEIPT_WITHOUT_PAYLOAD` in all three cases. A below-floor receipt is a
rollback warning, not proof that rollback occurred, because the checkpoint
payload needed to establish the retained state is absent.

**Recovery boundary:** `CONSISTENT_UNAUTHENTICATED` is deliberately not named
`ACCEPTED`. The classifier does not authenticate the receipt issuer, verify
that the receipt came from an independent system, establish either storage
location's durability, or prove that two writes were atomic. It is a pure
consistency classifier, not a storage transaction manager. A deployment must
implement payload and receipt persistence using a storage-specific atomic
transaction or a documented write-ahead protocol, retain the rollback floor
independently, and test actual crash behaviour at each persistence boundary.
If the storage layer cannot establish which state committed, recovery must
fail closed rather than infer acceptance.


### Single-file checkpoint acceptance envelope (v1)

`experiments/checkpoint_store.py` provides an initial filesystem persistence
adapter for the checkpoint/receipt pair. The envelope schema is
`experiments/schemas/audit-chain-checkpoint-acceptance-envelope-v1.schema.json`;
it references the existing strict checkpoint and acceptance-receipt schemas.

`build_checkpoint_envelope(checkpoint, acceptance_receipt)` rejects a
malformed checkpoint, unsupported fields, a receipt sequence mismatch, a
receipt digest mismatch, or a receipt time before the checkpoint anchor.
`write_checkpoint_envelope(path, checkpoint, acceptance_receipt)` serialises
the validated pair into one JSON file. It creates a temporary file in the
destination directory, flushes and fsyncs that file, then replaces the
destination with `os.replace`. Because both records are in one file, readers
cannot observe a newly written payload paired with an old receipt through
this adapter's normal read path. `load_checkpoint_envelope(path)` reads and
validates the complete envelope; it never synthesises a missing member.

The write result reports `ATOMIC_SAME_DIRECTORY_REPLACE`,
`file_fsync: CONFIRMED`, `directory_fsync` and
`storage_atomicity: SINGLE_ENVELOPE_ONLY`. On platforms exposing
`O_DIRECTORY`, the adapter fsyncs the parent directory after replacement.
If that fsync fails, `CheckpointEnvelopeDurabilityUncertain` is raised:
the replacement may already be visible, but crash durability is not
confirmed. Where directory fsync is unavailable, the result says
`directory_fsync: UNAVAILABLE`; it does not silently claim full durability.
A failed replacement leaves the previous destination intact and removes
the temporary file.

The optional `minimum_sequence` argument to `write_checkpoint_envelope(...)`
rejects a candidate below the caller-supplied floor before any write begins.
When supplied and met, the result reports
`rollback_floor_protection: CALLER_SUPPLIED_FLOOR_CHECKED_NOT_PERSISTED`;
when omitted, it reports `NOT_PROVIDED`. This is a comparison against the
value supplied by the caller, not proof that the floor is independently
retained, authenticated or rollback-resistant. The operator must continue to
obtain that value from independently protected state.

Before replacement, the adapter validates any existing destination envelope.
A candidate with a lower checkpoint sequence is rejected, preventing a stale
single writer from silently replacing a newer retained checkpoint. Reusing
the current sequence is permitted only when the complete envelope is identical;
that exact retry does not replace the file, but it re-fsyncs the existing file
and parent directory where supported so a prior uncertain durability result
can be re-evaluated. A retry fsync failure remains an explicit durability-
uncertain result. Different content at the same sequence is rejected. An
unreadable or invalid existing
envelope also blocks replacement rather than being silently overwritten.
This monotonic guard is scoped to the documented single-writer adapter; it is
not a compare-and-swap primitive and does not make concurrent writers safe.

**Scope boundary:** this is a single-writer, single-file filesystem adapter,
not a cross-platform transactional storage guarantee. It does not provide
inter-process locking or compare-and-swap protection against concurrent
writers. Atomic replacement semantics depend on the operating system and
filesystem. File fsync and directory fsync are evidence of requested flush
operations, not proof against every hardware,
controller, network-filesystem or power-loss failure. The adapter does not
authenticate the receipt, verify the event chain, protect the independently
retained rollback floor, coordinate multiple replicas, or provide backup
recovery. The caller must still pass the loaded checkpoint and receipt through
the recovery classifier with independently retained floor state. A successful
write must not be promoted to an authenticated or globally accepted state.

### External checkpoint-floor witness contract

`experiments/checkpoint_floor_witness.py` defines the `CheckpointFloorWitness`
adapter contract and verifies detached Ed25519 receipts. A provider must expose
`read_latest()` and an atomic `advance_floor(expected_witness_sequence,
minimum_checkpoint_sequence, idempotency_key)`. The advance operation must
compare-and-advance monotonically at the provider. It must durably bind each
idempotency key to the complete request (expected witness sequence and requested
floor), atomically commit that binding with the floor advance, and replay the
identical accepted receipt tuple for an exact retry even after provider process
restart. Reusing a key with different request parameters must be rejected.
A test double can exercise this contract, but cannot establish that a deployed
provider actually persists the binding or commits it atomically. The provider's
sequence, floor and idempotency records must be retained outside the local
checkpoint/ledger failure domain.

A receipt binds the witness ID, provider ID, declared failure-domain ID,
governance authority name, monotonic witness sequence, minimum checkpoint
sequence, previous-receipt digest and validity interval. Its signature uses a
separate domain prefix and the trust-store purpose
`CHECKPOINT_FLOOR_WITNESS`. Verification requires operator-pinned expected
identities, the local storage-domain identifier, a minimum witness sequence
maintained independently of the local ledger, and the required checkpoint
floor. A same-domain receipt is rejected. A distinct domain label is reported
only as `DECLARED_DISTINCT_NOT_INDEPENDENTLY_PROVEN`: it does not prove
separate ownership, infrastructure, administrators, backups or recovery.

A successful signature result is relative to the caller-supplied governance
trust store and configuration. It does not authenticate the authority, prove
provider operation, or prove event truth. The helper
`advance_checkpoint_floor_with_witness(...)` reads and verifies the current
receipt, advances the witness first using compare-and-advance, verifies the
returned receipt, then appends the resulting floor locally. The target is the
maximum of the requested floor, operator floor, current witness floor and
current local floor; it cannot lower either retained floor. If a concurrent
provider advance returns a still-higher signed floor, that exact higher floor
is copied into the local ledger. The returned receipt must be the immediate
next witness sequence and its `previous_receipt_sha256` must equal the digest
of the receipt read before the advance; a signed but discontinuous transition
is treated as uncertain and is not copied locally. The local ledger's parent directory and caller-supplied local recording
timestamp are preflighted before any external advance, so a known local-path
or timestamp error cannot needlessly mutate the remote floor. If the provider advance call
times out or returns an unverifiable receipt, it raises
`CheckpointFloorWitnessAdvanceUncertain` with the idempotency key; the provider
may already have advanced, so retry by reading its latest state and reusing
that key. If the local append fails after a verified witness advance, it raises
`CheckpointFloorWitnessLocalCommitUncertain` carrying the signed receipt and
idempotency key. Retry by reading the provider again and using the same key;
the helper converges the local ledger without issuing a second advance when
the provider already retains the target. A corrupt local ledger is not treated
as an empty ledger.

This is still not a distributed transaction or proof of atomic acceptance.
The provider adapter is not deployed, and provider-side atomicity/idempotency
must be demonstrated by its implementation. Do not advance acceptance based
solely on a local ledger when the required witness is unavailable or
unverifiable.

Schemas:
`experiments/schemas/audit-checkpoint-floor-witness-v1.schema.json` and
`experiments/schemas/audit-checkpoint-floor-witness-signature-v1.schema.json`.
The governance key must explicitly allow `CHECKPOINT_FLOOR_WITNESS`.

`classify_checkpoint_recovery_with_witness(...)` is the recovery-side gate.
It verifies the supplied witness receipt and requires its checkpoint floor to
equal the fully validated local ledger floor before invoking the recovery
classifier. An invalid witness returns `WITNESS_NOT_VERIFIED`; malformed receipt or
signature-envelope evidence is reported as `MALFORMED_WITNESS_EVIDENCE`.
Invalid operator configuration or governance material remains an explicit
caller error rather than being mislabelled as bad provider evidence. A floor
mismatch returns `WITNESS_LOCAL_LEDGER_DIVERGENCE`, distinguishing
`WITNESS_AHEAD_OF_LOCAL_LEDGER` from `LOCAL_LEDGER_AHEAD_OF_WITNESS`.
Missing or corrupt local history propagates an error. It never silently picks
the higher or lower source and never classifies recovery from a divergent pair.
Even a matching pair remains relative to caller-supplied governance material;
it does not establish authority identity or prove operational independence.

### Independent operator anti-rollback pin: restore test and deployment boundary

The witness verifier accepts minimum witness sequence and checkpoint floor as
caller-supplied policy inputs. They are not made durable or independent merely
because a caller labels them as operator values. The deployment must retain
both values in an operator-controlled trust domain outside the witness
provider's backup/restore boundary and outside the local checkpoint/ledger
failure domain. The operator must authenticate that retained state, prevent
unauthorised rollback, and atomically advance the pin with the corresponding
acceptance decision. A separately protected recovery copy must preserve the
latest accepted pin; after loss, restore and authenticate that copy before
resuming verification. If no trustworthy copy can be established, fail closed
and re-provision explicitly rather than deriving a new minimum from the
provider receipt being evaluated.

The test named
`test_restored_provider_backup_is_rejected_by_independently_retained_operator_floor`
models the critical rollback case: a valid sequence-8/floor-14 provider backup
is captured, the provider advances to sequence 9/floor 15, and the operator
retains minimums 9/15 outside the provider state. Restoring the old signed
provider backup leaves its signature valid under the old 8/14 policy, but the
same receipt is rejected as `ROLLBACK_REJECTED` against the retained 9/15
minimums. This is a verifier-level regression test only. It does not implement
operator pin storage, atomic acceptance, authenticated backup, or prove a
real provider's independence; those remain deployment obligations.

A companion negative-control test, `test_restoring_provider_and_operator_pin_backups_reopens_rollback`, restores both the old provider receipt and the old operator-policy backup. The old signed receipt is then accepted against the restored 8/14 policy. This is intentional: the anti-rollback guarantee collapses if the provider and operator pin can be rolled back together. The operator pin's backup, administration and recovery path must therefore be protected independently of the provider, not merely stored in a different file or labelled as a different domain.
The test `test_operator_pin_sequence_and_checkpoint_floor_are_independent_rollback_guards` also exercises each pin dimension separately: a newer witness-sequence minimum rejects the old receipt even when the checkpoint-floor minimum is unchanged, and a newer checkpoint-floor minimum rejects it even when the witness-sequence minimum is unchanged. Either coordinate is independently binding.



### Append-only local rollback-floor ledger

`experiments/checkpoint_floor_ledger.py` provides a separate JSONL
ledger for retaining a monotonically increasing minimum checkpoint sequence.
Each entry carries a contiguous ledger revision, the minimum checkpoint
sequence, a UTC recording time, the previous entry digest and its own
canonical SHA-256 digest. Loading validates the complete chain, revision
continuity, non-decreasing floor and timestamp, and every entry digest. A
missing ledger raises `FileNotFoundError`; an empty, truncated, malformed
or discontinuous ledger fails closed and is never interpreted as floor zero.

`append_checkpoint_floor(path, minimum_checkpoint_sequence, recorded_at_utc)`
creates the first entry or appends a higher floor. Lower floors are rejected.
An identical floor does not append a duplicate; it re-fsyncs the existing file
and its parent directory where supported so a retry can re-evaluate a prior
uncertain durability result. New appends fsync the ledger file and, where
supported, the parent directory. A failed file or directory fsync is reported
as durability-uncertain; a retry of the same floor rechecks both. A partial
append leaves an incomplete tail, which the loader rejects rather than
repairing or skipping.
The helper
`checkpoint_floor_value(path)` returns the latest validated floor for
passing to the checkpoint recovery classifier or the checkpoint envelope
writer. To reduce the chance of accidentally omitting the floor, deployments
may call
`classify_checkpoint_recovery_with_floor_ledger(events, checkpoint, receipt, path)`.
It loads and validates the ledger before classification, propagates missing or
invalid-ledger errors, and adds the ledger revision and entry digest to the
result. Its provenance label is explicitly
`LOCAL_APPEND_ONLY_LEDGER_NOT_AUTHENTICATED`; it does not upgrade the
classifier's unauthenticated status.

The matching schema is
`experiments/schemas/audit-chain-checkpoint-floor-ledger-entry-v1.schema.json`.
The ledger is append-only by API convention, not immutable storage. It is a
separate file, but a second file on the same disk is not an independent failure
domain. Writers are serialized with a persistent sidecar lock file and POSIX
exclusive advisory locking; the lock covers the complete read/validate/append/
fsync sequence. Readers take a shared lock on the same sidecar while loading a
snapshot, so cooperating readers cannot observe an in-progress append. The
writer validates through an internal unlocked loader while holding its
exclusive lock, avoiding nested-lock deadlock. The lock file is deliberately
not unlinked after release, so processes cannot accidentally lock different
inodes. This coordinates cooperating processes on a supported local POSIX
filesystem; it is not a distributed lock and must not be assumed reliable on
arbitrary network filesystems. On platforms without the required advisory-lock
facility, an append is refused rather than performed without writer
coordination; reads remain possible because the library cannot append there.
Authenticated entries, replication, backup protection and
rollback resistance if the ledger itself is replaced by an older copy remain
outside this implementation. Deployments must place protected copies in a
genuinely separate storage/failure domain. If the ledger is missing or invalid,
do not infer a floor from the checkpoint envelope or silently reset to zero.

## Authenticated operator pin ledger

`experiments/operator_pin_store.py` adds an append-only operator record for
the two independent checkpoint-witness rollback coordinates:
`minimum_witness_sequence` and `minimum_checkpoint_sequence`. Each entry
has a contiguous revision, non-decreasing coordinates, a non-decreasing UTC
recording time, a SHA-256 link to the preceding entry and an HMAC-SHA256
authentication tag. The HMAC key is supplied by the caller and must be
obtained from a separately managed secret store; it is never written to the
ledger. POSIX advisory locking serialises cooperating readers and writers.
A partial append, malformed tail, bad MAC, wrong key, coordinate regression
or missing/empty ledger fails closed. File and parent-directory fsync outcomes
are treated as durability boundaries, not universal power-loss guarantees.

The loader accepts optional `minimum_revision`,
`minimum_witness_sequence` and `minimum_checkpoint_sequence` arguments.
These values must come from a separately protected source. They detect a
restored older ledger even when its HMAC remains valid. Supplying values read
from the same ledger is not independent protection.

**Rollback boundary:** HMAC authenticates ledger content; it does not prevent
replay of an older correctly authenticated backup. The key must be protected
outside the ledger's storage and backup domain, and at least one independent
monotonic recovery source must retain the latest accepted revision and both
coordinates. If that independent source is unavailable or cannot be
authenticated, do not reset pins from the restored ledger or from the witness
receipt under evaluation; fail closed and explicitly re-provision. This module
is a persistence primitive, not a deployed key-management service or proof of
independent infrastructure.

The focused operator-pin regression command is
`python -m unittest discover -s tests -p 'test_operator_pin_store.py' -v`.

The helper `verify_checkpoint_floor_witness_with_operator_pins(...)`
connects the authenticated operator ledger to detached witness verification.
It supplies the latest authenticated witness-sequence and checkpoint-floor
pins to the existing verifier and can compare them with independently retained
minimum revision and coordinate values. A missing/corrupt ledger, wrong key,
or stale value below any supplied independent minimum raises an error before
witness verification. If independent minima are omitted, the result explicitly
reports that the independent rollback guard was not fully checked.

Recovery integration uses
`classify_checkpoint_recovery_with_operator_pins(...)`. This wrapper requires
all three independently retained minimums (pin revision and both coordinates),
then loads and authenticates the operator ledger before invoking the existing
external-witness/local-ledger recovery gate. It supplies both stored operator
minimums and refuses to classify if an independent minimum is absent, or if
the operator ledger is missing, malformed, has an invalid HMAC, or falls below
any independently retained minimum supplied by the deployment.
