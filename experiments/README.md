# Synthetic Vehicle-Event Collision Benchmark

This experiment applies the ∂ss return-check discipline to fictional parcel journeys.
It is inspired by the *method* of controlled experiments (prepare known conditions,
introduce disturbances, observe detector outcomes), not by particle physics itself.
No LHC data, physical collision data, live telemetry, customer records or licensed
address data are used.

## Run

```bash
python experiments/vehicle_collision_bench.py
python experiments/vehicle_collision_bench.py --total 10000 --seed 88 --json-out vehicle-bench.json
python -c "from experiments.vehicle_collision_bench import benchmark, generate_compound_dataset; import json; print(json.dumps(benchmark(generate_compound_dataset(1200)), indent=2))"
python -m unittest discover -s tests -v
```

## Experimental design

The default dataset contains 10,000 deterministic journeys:

- 5,000 clean journeys
- 1,000 with GPS distance above the declared 100 m threshold
- 1,000 with a parcel identity mismatch
- 1,000 with a destination identity mismatch
- 1,000 with non-monotonic event timestamps
- 1,000 with missing delivery proof

The evaluator returns `VERIFIED` only when all six declared checks pass.
Otherwise it returns `UNRESOLVED` and names the failed checks. This benchmark
does not attempt fuzzy correction.

## Evidence classification

An unresolved journey now carries an `evidence_class` as well as reason codes:

- `INSUFFICIENT`: a required observation or reference is absent (for example, no delivery GPS or proof reference).
- `CONFLICTING`: observations contradict a declared invariant (for example, parcel identity changes or event timestamps run backwards).
- `MIXED`: at least one required item is missing and at least one observed item conflicts.
- `SUFFICIENT_AND_CONSISTENT`: all required evidence is present and all declared checks pass.

All unresolved classes remain `UNRESOLVED`; missing information is never promoted
to a successful verification. Malformed journey objects, malformed event records,
missing identity fields, duplicate/out-of-order event types, invalid timestamps and
negative or non-finite GPS distances are refused with reason codes rather than allowed
to crash the evaluator. Individually valid event records are still inspected when a
sibling record is malformed, so a schema defect does not erase independent observed
identity conflicts or other evidence. The GPS boundary is inclusive: exactly 100 m passes this
illustrative rule; any larger value fails. A proof reference is checked for presence
only, not cryptographic authenticity or independent authority. GPS is a supplied
distance value, not a raw-coordinate measurement. Timestamps are synthetic numeric
ticks used only for ordering; they do not represent wall-clock time or a timezone.

## Compound-disturbance experiment

The `generate_compound_dataset(1200)` experiment contains 400 clean journeys and
800 journeys carrying two or three simultaneous disturbances. It covers every
pair and every triple drawn from the five disturbance classes, with balanced
representation. This tests combinations rather than only isolated faults. Run it
from Python with:

```python
from experiments.vehicle_collision_bench import benchmark, generate_compound_dataset
report = benchmark(generate_compound_dataset(1200, seed=88))
print(report)
```

The generated compound cases are still rule-shaped synthetic tests; they are not
independent evidence of field performance.

A permutation test applies every pair and triple in every possible injection order.
For the current five anomaly classes, the resulting event evidence and evaluator
trace must be identical regardless of ordering. This checks that the compound
results are not an accidental consequence of which fixture mutation ran last.

The report's `pair_interaction_matrix` evaluates every unordered anomaly pair
co-occurring in a compound journey. Each pair records both-detected, first-only,
second-only and neither-detected outcomes, per-fault and joint detection rates,
and observed reason-code and terminal-state counts. Pairs are also counted inside three-anomaly journeys, so
these figures describe pair co-occurrence within the full compound dataset rather
than only isolated two-fault trials. The matrix is computed after evaluator output
is produced; synthetic labels remain benchmark-side oracle metadata.

## Reported measures

- **Anomaly detection rate:** injected anomalous journeys returned as `UNRESOLVED`
- **False accepts:** injected anomalous journeys incorrectly returned as `VERIFIED`
- **Clean acceptance rate:** clean journeys returned as `VERIFIED`
- **False rejects:** clean journeys incorrectly returned as `UNRESOLVED`
- **Reason-code frequency:** number of evaluated journeys carrying each reason code
- **Reason combinations:** frequency of each exact, sorted reason-code set (joined with ` + `)
- **Condition-level fingerprints:** reason-code and exact-combination counts grouped by the synthetic injected condition
- **Anomaly-to-invariant matrix:** each injected disturbance is mapped to its declared evaluator reason code; matrix rows show all reason codes observed in journeys carrying that disturbance
- **Per-anomaly detection:** injected, detected, missed and detection-rate counts for each disturbance
- **Clean reason-code counts:** any evaluator refusal reason appearing in journeys labelled clean
- **Interaction fingerprints:** exact reason-code combinations for controlled cases where one disturbance creates a secondary symptom or masks the primary diagnostic code
- **Interaction diagnostic summaries:** per-fixture counts of primary detections, missed primary diagnoses, diagnostic statuses and secondary symptoms
- **Pairwise interaction matrix:** for every anomaly pair appearing in compound journeys, counts cases where both expected reason codes, only the first, only the second, or neither were observed, alongside reason-code and terminal-state frequencies

Two interaction fixtures are available through `make_interaction_journey`:

- `reordered_events` + `sequence_echo`: the journey carries both a timestamp-order conflict and an event-sequence mismatch. The primary invariant remains detectable while the secondary symptom is exposed.
- `wrong_parcel` + `missing_parcel_masks_conflict`: the delivery parcel field is then made blank. The evaluator reports the missing field rather than the underlying identity conflict. The primary injected fault is therefore refused but not specifically diagnosed by its expected reason code.
- `wrong_parcel` + `missing_parcel_with_separate_conflict`: a different event's parcel field is made blank while the wrong delivery identity remains observable. The evaluator must report both the missing field and the separate identity conflict.
- `wrong_destination` + `missing_destination_with_separate_conflict`: the same independent-evidence check for destination identity.

These are deliberately constructed diagnostic stress cases, not statistical models of how often such interactions occur. A refusal can be correct while its diagnostic attribution is incomplete; the per-anomaly detection measure makes that distinction visible.

Identity diagnosis is field-aware rather than mutually exclusive: a missing value
must not suppress a contradictory non-empty value observed in another event. Parcel
and destination expectations are also validated independently: an absent expected
parcel ID must not suppress an independently testable destination conflict, and an
absent expected destination ID must not suppress a parcel conflict. The aggregate
`EXPECTED_IDENTITY_FIELDS_MISSING_OR_INVALID` reason and
`expected_identity_fields_present` check remain for compatibility. The trace also
exposes `expected_parcel_id_present` and
`expected_destination_id_present` separately, with specific reason codes
`EXPECTED_PARCEL_ID_MISSING_OR_INVALID` and
`EXPECTED_DESTINATION_ID_MISSING_OR_INVALID` when either reference is absent.
When the only conflicting value itself is erased, the evaluator cannot infer it
and reports only what remains observable. This distinguishes evidence loss from
reason-code precedence.


The benchmark report also includes a separate provenance consistency audit over
all evaluated journeys. It checks exact reason-code coverage (no missing or orphaned
entries, and no duplicate entry for a reason), validates each generated finding
against its underlying journey/event field and original event index, and reports
when distinct findings legitimately share an event. The independent audit mapping
covers every evaluator reason code, including malformed records, missing expected
identity references, interaction fixtures and the clean success marker. It does not
consume injected labels. The clean success marker is checked directly against the
journey invariants rather than by asking the evaluator to re-verify itself. The
audit independently derives the complete expected reason-code set from journey
evidence, so deleting both a reported reason and its provenance entry cannot
silently make a trace appear complete. It rejects malformed reason-code values.
It also independently recomputes every declared check, the evidence class and
the terminal state from the journey. Mutation tests alter or remove individual
checks, add an unearned check, and falsify both accepted and refused terminal
states; the audit must reject each altered decision contract. Non-object result
values and non-string reason-code entries are also treated as malformed findings;
the audit returns an invalid trace rather than raising an exception. Dataset-level
auditing preserves one result per journey and aggregates these malformed-result
failures without aborting the full audit. The aggregate auditor also validates its outer inputs: `journeys` must be a list and `results` must be a list or `None`; malformed collection containers are rejected explicitly rather than being iterated accidentally. Additional mutation coverage replaces
decision fields and trace collections with nulls, scalars, lists and mappings of
the wrong shape; each altered result must be rejected. Clean dataset audits also
assert zero decision mismatches in their aggregate counters.
A deterministic nested-mutation matrix additionally exercises JSON-shaped corruption
across decision fields, reason-code collections, provenance entries, and event-index
members (including booleans, floats, negative values, strings and nested containers).
Every mutated trace must be rejected without an audit exception. Separately, deterministic pairwise mutations of source journey fields and event evidence exercise evaluator/auditor agreement across clean and compound-fault baselines; malformed event-container shapes are tested independently. A fixed-seed mutation walk adds 256 reproducible cases, each combining one to four malformed source-evidence changes across clean and compound-fault baselines; every evaluator trace must remain auditable and unresolved. A separate 96-row seeded dataset test verifies that per-trace decision tampering is counted exactly by the aggregate audit and cannot disappear in batch reporting. It reconciles every aggregate counter—including provenance coverage, unsupported findings, invalid pointers, decision mismatches and shared-event references—against the individual trace audits. Pairwise combinations of decision, reason, provenance, pointer and rule tampering are also exercised to expose compound-corruption interactions.
The checker also refuses malformed trace collections and malformed event-index lists
without crashing. It can also audit the refusal trace for a non-object journey
input. It verifies the exact declared rule text for each finding, not merely that
the explanation is non-empty. Mutation tests alter evidence kind, source, field,
event index and rule independently; duplicate entries and fabricated findings
must also be rejected. It also detects a reason code and its evidence entry being
removed together, because expected findings are derived independently from the
journey rather than only compared with the submitted trace. Audit failures are reported as data and do not change evaluator
terminal states.

Each evaluator trace now includes `evidence_provenance`, a deterministic list with
one entry per emitted reason code. Each entry identifies the evidence kind
(`missing`, `conflict` or `consistent`), source, field names, original zero-based
event indices and the declared comparison rule. Event indices refer to the input
list before malformed records are skipped, so an auditor can locate evidence in
the original journey. Provenance records deliberately omit raw observed and
expected values; they provide locations and rules without duplicating potentially
sensitive identity data. The success marker receives a `consistent` provenance
entry and remains distinct from failure findings. These are evaluator-produced
evidence pointers, not cryptographic attestations or proof that upstream source
data is authentic.

The report's `interaction_diagnostic_summary` keeps these fixture outcomes separate:
it counts primary detections and misses, diagnostic statuses and observed secondary
symptoms for each named interaction. This makes a masking failure visible without
relying on a reader to reconstruct it from individual traces.

The declared oracle mapping is explicit: `gps_drift` → `DELIVERY_GPS_OUTSIDE_LIMIT`,
`wrong_parcel` → `PARCEL_IDENTITY_CONFLICT`, `wrong_destination` →
`DESTINATION_IDENTITY_CONFLICT`, `reordered_events` → `TIMESTAMP_ORDER_CONFLICT`,
and `missing_proof` → `DELIVERY_PROOF_REFERENCE_MISSING`. For compound journeys,
each injected disturbance is counted as one occurrence. A disturbance is detected only
when its mapped reason code appears in the evaluator's reason list. Other reason codes
in that same row remain visible, exposing co-occurrence and unexpected classifications.
This is a test-oracle mapping for the synthetic generator, not a claim that every real
operational fault has one unique diagnostic signature.

`by_condition` is the oracle-condition × evaluator-terminal-state matrix: the left-hand labels
come from the generator's `injected_condition` metadata, while terminal states and reason
codes come from the evaluator. The evaluator does not read that metadata. This separation
keeps the expected synthetic condition from influencing the observed decision. The report
sorts keys for deterministic, JSON-friendly output. A clean journey's
`ALL_DECLARED_CHECKS_PASSED` marker is counted like any other reason code for frequency
accounting; it is a success marker, not a failure.

## Oracle-relative diagnostic traces

Each benchmark report now includes a deterministic `diagnostic_records` list and
`diagnostic_status_counts`. These records are created **after** the evaluator has
returned its evidence-derived trace. They compare the evaluator's observed reason
codes with the generator's synthetic oracle mapping; they are not evaluator inputs.

For a single injected disturbance, the record names the `primary_fault`, its
`expected_reason_code`, whether that code was detected, all observed reason codes,
and `secondary_symptoms` (observed codes other than the expected primary code).
Statuses are:

- `PRIMARY_IDENTIFIED`: the expected primary code appears without additional symptoms.
- `PRIMARY_IDENTIFIED_WITH_SYMPTOMS`: the expected primary code appears alongside other findings.
- `PRIMARY_MASKED`: the journey is refused, but the expected primary code is absent.
- `UNATTRIBUTED`: there is no single injected primary fault, or an anomalous case was not refused.
- `CLEAN`: no disturbance was injected.

Compound cases are deliberately marked `UNATTRIBUTED` at the single-primary level;
their injected faults and observed codes remain available in the record. No numeric
confidence score is reported: this experiment has no calibrated probability model.
The diagnostic trace is an oracle-relative benchmark assessment, not a claim that
the evaluator independently knows the injected cause. A correct refusal can still
have incomplete diagnostic attribution.

## Interpretation and limitations

A perfect score on this generated dataset demonstrates only that the implementation
enforces its own explicit rules against the disturbances deliberately injected.
It does **not** establish real-world GPS accuracy, proof-of-delivery reliability,
address resolution accuracy, fraud detection, operational performance or superiority
over a courier's existing systems.

The 100 m GPS threshold is an illustrative test parameter, not a recommended
universal delivery radius. Real deployment would require domain-specific tolerances,
clock and event semantics, trusted identity sources, data protection review,
representative labelled data and independent baseline comparison.

The benchmark is a deterministic test instrument, not a production tracking system.

## Synthetic address mutation matrix

Run the deterministic field-mutation benchmark:

```bash
python experiments/address_mutation_bench.py
python experiments/address_mutation_bench.py --json-out address-mutation-report.json
```

The matrix contains 18 fictional cases: one clean baseline, one case/whitespace
formatting-only case, eight isolated mutations (premise, street deletion/substitution/insertion,
multiple-edit street, adjacent transposition, locality and postcode), and six pairwise combinations across identity fields. Two additional cases exercise
multiple exact candidates and multiple near candidates, including reversed candidate
order to confirm that ambiguity does not become acceptance. The street boundary cases
also distinguish one-character deletion, substitution and insertion (permitted by the
current Levenshtein rule) from a two-edit adjacent transposition (refused).
Expected terminal states and reason codes are benchmark-side oracle labels, stored
outside the case object passed to the evaluator. Comparison occurs only after
evaluation. The report includes state/reason counts, per-case expected and observed
results, oracle mismatches and semantic-mutation false accepts; formatting-only equivalence
is not counted as a false accept. It also independently audits every candidate trace against
the synthetic case evidence, reporting audited case/candidate counts and any trace mismatches.
The audit receives no oracle labels. The benchmark exits non-zero on an oracle mismatch,
a candidate-trace audit mismatch or any VERIFIED result after a premise, street, locality
or postcode identity mutation.

The cases exercise the current narrow contract: formatting normalisation is
case-folding plus whitespace collapse; one street edit can be CORRECTED only when
premise, locality and postcode agree; premise/locality conflicts fail candidate
retrieval; postcode conflicts fail the return check; multiple street edits have no
supported candidate. Pairwise cases ensure a near street cannot override a protected
identity conflict. This is a rule-shaped synthetic conformance matrix, not a
representative sample, calibrated error rate or real-world accuracy estimate. No
real addresses, customer data, PAF data or external address services are used.


## Atomic checkpoint acceptance envelope

The filesystem adapter `experiments/checkpoint_store.py` stores one validated
checkpoint payload and its acceptance receipt in a single JSON envelope.
Run its focused tests with:

```bash
python -m unittest discover -s tests -p 'test_checkpoint_store.py' -v
```

The adapter fsyncs the temporary file before same-directory `os.replace`,
then fsyncs the parent directory where `O_DIRECTORY` is available. Its result
distinguishes replacement, file flush and directory flush. A directory-fsync
failure after replacement raises `CheckpointEnvelopeDurabilityUncertain`;
the new file may be visible even though crash durability is unconfirmed.
The adapter assumes a single writer; it does not provide inter-process locking or compare-and-swap protection against concurrent writers. The adapter protects only the pair's single-file visibility. It does not
authenticate the receipt, protect the independent rollback floor, or establish
a universal filesystem/power-loss guarantee. See the commercial pilot protocol
for the complete scope boundary.


## External checkpoint-floor witness

`experiments/checkpoint_floor_witness.py` defines the signed witness receipt
contract, provider protocol, witness-first floor coordination and recovery gate.
A provider must implement atomic compare-and-advance and durable idempotency
outside the local ledger's failure domain. Each idempotency key is bound to the
complete request (expected witness sequence and requested floor); an exact retry
must replay the identical accepted receipt tuple after provider restart, while
reuse with different request parameters must be rejected. The key binding and
floor advance must commit atomically. Each returned advance receipt must be
the immediate next witness sequence and hash-link to the exact prior receipt
read by the coordinator; a valid signature alone does not establish continuity.
The coordinator also validates the local recording timestamp before external
advance, so invalid local append metadata is rejected without remote mutation. The verifier binds expected provider
and witness identifiers, declared failure domain, Ed25519 governance key,
witness sequence and checkpoint floor. The recovery gate refuses to classify
when the external and local floors diverge, or when either retained source is
missing or invalid. Structurally malformed witness receipts and signature
envelopes are classified as `WITNESS_NOT_VERIFIED` /
`MALFORMED_WITNESS_EVIDENCE`; invalid caller-supplied policy configuration
remains an explicit error.

Run the focused tests with:

```bash
python -m unittest discover -s tests -p 'test_checkpoint_floor_witness.py' -v
```

A rollback regression also captures a genuine signed sequence-8/floor-14
provider backup, advances to sequence 9/floor 15, then restores the old provider
state while retaining operator minimums 9/15 separately. The old signature
still verifies under the old policy but is rejected against the retained
minimums. This demonstrates the verifier's conditional anti-rollback
behaviour; it does not implement durable operator pin storage or prove
independent backup protection.
A companion negative-control regression restores both the old provider backup and the old 8/14 operator-policy backup; the old signature is then accepted again. This deliberately demonstrates that the protection fails if both state sources can be rolled back together. The operator pin's backup and recovery path must be independently protected, not merely separated by filename or declared domain label.
A focused test also proves that either retained coordinate independently rejects the old receipt: witness-sequence minimum 9 with floor minimum 14, or witness-sequence minimum 8 with floor minimum 15.

These tests use a synthetic provider with a shared idempotency-state fixture
to simulate adapter recreation with retained state, exact-result replay and
key/request mismatch. They do not establish a live provider's persistence,
atomicity, independent administration or storage separation. A distinct failure-domain label is not proof of independence.
Successful verification remains relative to caller-supplied governance and
operator configuration; authority authentication and event truth remain
unestablished. See the commercial pilot protocol before integrating a provider.

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

Run its focused regression tests with:

```bash
python -m unittest discover -s tests -p 'test_operator_pin_store.py' -v
```

The test suite covers independent coordinate monotonicity, HMAC tampering,
wrong-key rejection, stale-backup detection when independent minima are
retained, idempotent retries, concurrent writers and partial-append failure.

The integration helper
`verify_checkpoint_floor_witness_with_operator_pins(...)` loads and
authenticates the retained operator ledger, then supplies its latest witness
sequence and checkpoint floor directly to the existing witness verifier.
Optional independent minima are checked before verification. Its result
reports the operator pin revision, entry digest, HMAC verification and whether
all three independent minima were supplied. The helper does not infer those
minima or establish that their source is operationally independent.

The companion helper
`classify_checkpoint_recovery_with_operator_pins(...)` places the authenticated
operator ledger in front of the existing witness/local-ledger recovery gate.
It loads and authenticates both operator coordinates, checks any separately
retained minimum revision and coordinates, then passes the stored minimum
witness sequence and checkpoint floor into recovery classification. It adds
the operator pin revision, entry digest, authentication state and independent-
minimum status to the recovery result. Missing, invalid or stale operator pin
state fails before recovery classification.
