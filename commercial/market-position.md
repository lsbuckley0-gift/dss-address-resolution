# ∂ss — Commercial Market Position

**Working category:** Auditable address-resolution control layer  
**Initial market:** UK organisations processing address records at scale  
**Positioning:** A verification and decision-trace layer that can sit around an existing address candidate-generation or authoritative reference-data service.

## One-sentence proposition

∂ss preserves the intended destination, evaluates candidate evidence, permits only an authorised correction, and checks the result back against the original intention—returning **VERIFIED**, **CORRECTED**, or **UNRESOLVED** with a traceable reason.

## The problem we address

Address-data workflows must handle incomplete, mistyped, stale, duplicated and conflicting records. A candidate that looks textually similar is not automatically the intended delivery point. An unsafe automatic acceptance can propagate into fulfilment, customer records, billing, eligibility checks and downstream systems.

The product proposition is not that fuzzy matching is new. Address parsing, candidate retrieval, ranking and confidence scoring are established approaches. ∂ss is positioned around the control decision after candidate generation: what evidence authorises a landing, what operation was performed, and did the return check preserve the intended destination?

## The ∂ss control loop

1. **Intended record:** preserve the input and its provenance.
2. **Resolution:** gather candidate(s) and evidence; allow no candidate or multiple candidates.
3. **Operation:** apply only a permitted, recorded transformation.
4. **Return check:** compare the observed result to the intended record using explicit, field-aware rules.
5. **Terminal state:** VERIFIED, CORRECTED or UNRESOLVED; record evidence, rules, version and reason.

An unresolved result is a valid outcome. It is not a system failure to be hidden by an arbitrary best-match selection.

## Differentiation to validate

- Explicit separation of candidate similarity from verified destination identity.
- A return-check gate after an operation, not merely a score attached to a candidate.
- First-class unresolved decisions and human-review routing.
- A decision trace that can be replayed and audited.
- Configurable field-level tolerances and invariants, rather than one opaque global score.

These are product hypotheses until demonstrated against representative customer data and compared with the customer's existing workflow.

## Initial buyer hypotheses

Prioritise discovery with:
- Parcel, courier and last-mile operators.
- Retailers and e-commerce operations with high address-change or failed-delivery costs.
- Utilities and service providers maintaining premise/customer records.
- Public-sector data teams performing record linkage.

Do not claim all these sectors are equally suitable. Start where the buyer can provide labelled cases, quantify error costs and run a controlled pilot.

## Competitive and ecosystem context

- Royal Mail's PAF and address-management ecosystem provide authoritative postal reference data and validation products. ∂ss should not claim to replace PAF or independently certify postal deliverability.
- The ONS has published an address-matching pipeline using parsing, candidate retrieval, ranking and confidence evaluation. This is evidence that address matching is a mature technical field.
- The NHS Gazetteer Service exposes PAF-based address validation and candidate search for eligible use cases. PAF licensing and end-user rights must be checked before deployment.
- The credible opening is therefore an auditable control layer and integration pattern, not a claim to be the first address matcher.

## Claims policy

Until independently tested, say:
- "Designed to make unsafe acceptance explicit."
- "Provides a traceable resolution workflow."
- "Supports VERIFIED, CORRECTED and UNRESOLVED outcomes."

Do not say:
- "Zero false accepts."
- "100% accurate."
- "More accurate than Royal Mail / ONS / Experian."
- "Production-ready" unless deployment, security, reliability and operational tests establish it.
- "PAF compliant" or "PAF licensed" without the relevant licence and technical review.

## Commercial route

1. Discovery interview and workflow mapping.
2. Customer-approved, legally usable, labelled evaluation dataset.
3. Fixed-scope paid proof of concept.
4. Independent evaluation against the customer's current baseline.
5. Integration and enterprise licence only if the pilot meets agreed acceptance criteria.

## Success condition

A buyer should be able to answer, from evidence: how many wrong destinations were accepted before and after; how many cases became unresolved; how much human review was required; what latency and cost were added; and whether every automated decision can be explained and replayed.
