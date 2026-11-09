# Synthetic ∂ss demonstration

This folder contains a small, dependency-free Python demonstration of the ∂ss decision loop.

All records in `cases.json` are fictional test data. They are not real addresses and must not be used for delivery, customer records or operational decisions.

## Run

From the repository root:

```bash
python demo/dss_demo.py
python demo/dss_demo.py --json-out demo-trace.json
python -m unittest discover -s tests -v
```

No third-party packages are required.

## What it demonstrates

- `VERIFIED`: one candidate matches all declared fields after case/whitespace normalisation.
- `CORRECTED`: one candidate is unique under the demonstration retrieval rule, and the return check passes.
- `UNRESOLVED`: no candidate, multiple candidates, or a failed return check.

The return check requires exact agreement on premise, locality and postcode, and permits at most one edit in the street field for the typo-correction example. This is a deliberately narrow teaching rule, not a universal address-identity policy.

## Important limits

This is a reference demonstration, not a production matcher or evidence of accuracy. It does not use PAF, live address data, geocoding, postal validation or customer records. It has no production security, privacy, monitoring, resilience or integration controls. The synthetic scenarios are hand-authored and are not a representative benchmark.

A customer pilot must use an authorised, labelled dataset, a frozen baseline and pre-agreed acceptance criteria as described in [the pilot protocol](../commercial/pilot-protocol.md).
