# RFC 3161 TSA revocation-evidence profile (design boundary)

**Status:** design-only; not an implemented verifier feature  
**Profile identifier:** `rfc3161-tsa-revocation-evidence/v1-draft`

This document defines the minimum questions a future CRL/OCSP implementation must answer before it may change the current result fields. It does not accept, parse, authenticate or evaluate revocation evidence. The RFC 3161 verifier must continue to report:

- `tsa_certificate_revocation: NOT_CHECKED`
- `historical_revocation_assurance: NOT_ESTABLISHED`

No input file, schema declaration or successful timestamp path check may upgrade those values by implication.

## 1. Separate the claims

The following are different assertions and must never be collapsed into one boolean:

| Claim | Meaning |
|---|---|
| Certificate identity | The evidence identifies the exact TSA signing certificate used for this token. |
| Evidence authenticity | The evidence signature and signer authorization validate under an explicitly supplied issuer/trust context. |
| Status at evidence time | The evidence asserts a status at its own stated `thisUpdate` / CRL issue time. |
| Status at token time | A defined policy and evidence history support a status conclusion at the token's asserted `genTime`. |
| Trust in the clock | The time used to interpret the evidence is independently governed. |

The token's `genTime` is TSA-asserted. It is not an independently trusted clock merely because the token signature verifies. Any future result must preserve that qualification.

## 2. Certificate identity binding

Before evaluating status, the verifier must derive the TSA signer certificate from the successfully verified timestamp token and bind evidence to that exact certificate.

The binding record must include, at minimum:

- SHA-256 digest of the exact DER-encoded TSA certificate;
- certificate issuer distinguished name and issuer public-key identity;
- certificate serial number, represented without lossy integer/string conversion;
- certificate validity interval;
- the token signer-certificate selection result and the chain context used to reach the caller's trust anchor.

A serial number alone is insufficient: serial numbers are unique only within an issuer context. An evidence item for a different certificate, issuer key, chain or token signer must be rejected, not treated as a near match.

The evidence must not be allowed to nominate a different TSA certificate from the one actually used to verify the token.

## 3. CRL evidence requirements

A CRL path, if implemented, must validate all of the following before its contents can affect status:

1. DER parsing succeeds and the CRL signature verifies under the authenticated CRL issuer key.
2. The CRL issuer is authorized for the target certificate's issuer and the CRL distribution-point scope matches the certificate and the requested status check.
3. Authority Key Identifier / issuer-key binding is checked where present and required by the applicable profile.
4. `thisUpdate`, `nextUpdate`, CRL number and applicable critical extensions are parsed and policy-checked. Missing or malformed required time/scope data is not a clean status.
5. The target certificate issuer and serial are matched exactly. Indirect CRL certificateIssuer processing must be correct before such CRLs are accepted.
6. Reason coverage is complete for the claim. A CRL limited by `onlySomeReasons` cannot establish absence of revocation for reasons outside its scope.
7. Delta CRLs are rejected unless the implementation can authenticate and correctly combine the delta with its exact compatible base CRL, including scope, base number, ordering and `removeFromCRL` semantics.

For v1 implementation planning, the safest first supported subset is a complete, direct CRL covering all relevant reason codes. Indirect CRLs, delta CRLs, partitioned reason scopes and other advanced forms should return an explicit unsupported/incomplete result until independently tested. They must not be silently treated as complete CRLs.

A missing serial in an incomplete, stale, wrong-issuer or wrong-scope CRL is **not** evidence of a good certificate.

## 4. OCSP evidence requirements

An OCSP path, if implemented, must validate:

1. The response status is successful and the BasicOCSPResponse parses strictly.
2. The matching SingleResponse CertID identifies the exact certificate using the issuer-name hash, issuer-key hash, hash algorithm and serial number; a serial-only match is insufficient.
3. The response signature verifies and the responder is authorized for this issuer. A delegated responder certificate must satisfy the applicable issuer relationship and OCSP-signing EKU requirements, and its own path and status policy must be evaluated.
4. `producedAt`, `thisUpdate`, optional `nextUpdate`, status and any `revocationTime` are parsed and policy-checked.
5. The response is bound to the request/nonce when a nonce was used; unsolicited or mismatched response data is not accepted as the answer to that request.
6. Exactly one applicable response is selected. Missing, duplicate-ambiguous, `unknown`, malformed, stale, future-dated or unauthorized responses cannot produce a good-status result.

A `good` OCSP status is not proof that the certificate was validly issued, nor does a single later `good` response by itself prove the certificate was unrevoked at an earlier token time. The response's status-time semantics and the policy's target instant must be explicit.

## 5. Time model: no retrospective shortcut

Every future evaluation must retain these separate instants:

- `token_gen_time`: time asserted inside the RFC 3161 token;
- `evidence_this_update`: time at which the CRL/OCSP status is stated to be known;
- `evidence_produced_at`: time the OCSP response was signed, when present;
- `evidence_next_update`: end of the stated evidence freshness interval, when present;
- `revocation_time`: issuer/responder-reported revocation time, when the certificate is reported revoked;
- `verification_observed_at`: caller's observation clock, with its trust level stated separately.

The implementation must distinguish at least two evaluation modes:

**Snapshot mode.** The policy asks whether evidence asserts status for a specified instant and accepts an evidence validity interval that covers that instant. This is a bounded status assertion, not proof that no undisclosed revocation event occurred between status production and the target instant. The policy must state the permitted freshness window and treatment of missing `nextUpdate`.

**Retrospective-history mode.** The policy asks what can be established about status at an earlier instant using evidence obtained later. This requires a complete, authenticated status history or an authoritative issuer statement whose semantics cover the earlier instant. A later OCSP `good` response, or absence from one later CRL, must not be promoted into historical proof without a defined history-completeness argument. A reported `revocationTime` later than the target instant is relevant only after the revocation statement itself is authenticated and its temporal semantics are accepted by policy.

If the evidence cannot support the requested mode, return an indeterminate/not-established outcome. Do not choose whichever timestamp makes the evidence look favourable.

## 6. Result vocabulary and fail-closed outcomes

A future implementation should expose independent dimensions rather than one `revoked: false` field. Proposed vocabulary (not yet an API contract):

- `NOT_SUPPLIED`
- `NOT_CHECKED`
- `EVIDENCE_MALFORMED`
- `EVIDENCE_SIGNATURE_INVALID`
- `EVIDENCE_SIGNER_UNAUTHORIZED`
- `CERTIFICATE_IDENTITY_MISMATCH`
- `EVIDENCE_SCOPE_INCOMPLETE`
- `EVIDENCE_STALE`
- `EVIDENCE_TIME_INCOMPATIBLE`
- `STATUS_REVOKED_AT_TARGET_TIME`
- `STATUS_GOOD_AT_EVIDENCE_TIME_ONLY`
- `STATUS_GOOD_AT_TARGET_TIME_UNDER_POLICY`
- `STATUS_UNKNOWN`
- `HISTORICAL_STATUS_NOT_ESTABLISHED`

The final two positive-looking statuses must carry the evidence references, target instant, evaluation mode, policy identifier/version and every relevant time field. No positive status may be emitted when issuer authorization, identity binding, evidence scope or time policy is unresolved.

A CRL/OCSP status result must not upgrade `timestamp_authentication`, `anchor_provenance`, `governance_authentication` or `event_truth`. Those are separate claims with separate trust roots.

## 7. Evidence envelope and retention

A future evidence envelope should be versioned and content-addressed. It should retain the original DER bytes, SHA-256 digest, media/type identifier, acquisition reference, acquisition time and acquisition-clock trust label, plus the parsed fields and validation trace. Parsed JSON alone is not a substitute for the signed DER object.

The envelope must identify:

- exact target certificate digest, issuer identity and serial;
- evidence type (complete CRL, delta CRL with its base, or OCSP response);
- evidence object digest and original bytes;
- signer certificate/key identity and authorization path;
- evidence scope and coverage;
- all source timestamps and the policy evaluation instant/mode;
- parser/verifier version and explicit unsupported features;
- result and reason codes sufficient to reproduce the decision.

Acquisition URLs and transport success are provenance metadata, not proof of authenticity. The verifier must not fetch arbitrary distribution URLs implicitly as a side effect of checking a timestamp.

## 8. Draft evidence-envelope schema

`experiments/schemas/rfc3161-tsa-revocation-evidence-v1-draft.schema.json`
defines a draft capture envelope for the original CRL or OCSP DER bytes,
their SHA-256 digest, acquisition metadata, target-certificate identity and
unverified identifiers claimed by the evidence. CRL and OCSP binding fields
are distinct: CRLs bind issuer name and serial in their entries; OCSP CertID
binds issuer-name hash, issuer-key hash, hash algorithm and serial.

The schema deliberately labels parser observations as untrusted. The
pinned Draft 2020-12 validator checks structural conditions, including the
different CRL and OCSP identifier requirements. Tests cover valid examples,
missing issuer/CertID bindings, unknown fields, digest syntax and UTC-time
format. These checks do not decode DER, verify the evidence digest against the
bytes, authenticate signatures, authorize responders, establish CRL scope or
decide certificate status. CI also checks the schema's JSON syntax. This draft
is not consumed by the RFC 3161 runtime API.

### Signer-certificate extraction feasibility

The synthetic OpenSSL integration suite now exercises
`openssl cms -verify -binary -inform DER -noverify -signer ...` against an
ephemeral RFC 3161 token. The test verifies that CMS signature/content
verification succeeds and that the extracted signer certificate's SHA-256
fingerprint equals the exact synthetic TSA certificate used to create the
token. This is a tested extraction route for a future implementation to
identify the token signer before certificate-specific revocation evaluation.

The `-noverify` option disables CMS signer's certificate-chain validation; it
does not mean the CMS signature/content check is skipped. The extraction
operation must therefore remain separate from the existing
`openssl ts -verify` path and must never replace its timestamp imprint,
timestamping-purpose or certificate-path checks. OpenSSL's timestamp
verification implementation requires exactly one CMS signer and checks the
signer's chain against the RFC 3161 `SigningCertificate` / RFC 5816
`SigningCertificateV2` identifier before accepting the token. The follow-on
CMS extraction therefore reads identity from the same token only after that
stricter timestamp verification has passed. It does not check revocation.
The runtime now performs this extraction only after
`openssl ts -verify` succeeds. It exposes the signer certificate's DER
SHA-256, signer SubjectPublicKeyInfo SHA-256, issuer-name DER SHA-256, exact
issuer-certificate DER SHA-256, issuer SubjectPublicKeyInfo SHA-256 and
lowercase hexadecimal serial under `tsa_signer_certificate`. If the signer
certificate is not embedded in the token, the same caller-supplied untrusted
certificate bundle is offered to CMS as a signer-certificate candidate; no
network retrieval occurs. The issuer certificate is selected from the
caller-supplied anchor/intermediate bundle using the signer's issuer name and
Authority Key Identifier; zero or multiple matches fail identity extraction
rather than guessing. Tests cover an unrelated same-name issuer key, an
ambiguous same-key issuer certificate, and a token with no embedded signer
certificate. These fields supply exact identity inputs for a future
revocation check; they do not assert that the certificate is unrevoked. If extraction fails, the timestamp result
remains `VALID` when the original RFC 3161 verification passed, while
`tsa_signer_certificate_identity` becomes `NOT_EXTRACTED` and revocation
remains `NOT_CHECKED` / `NOT_ESTABLISHED`. A focused test covers this
failure boundary.

The test uses ephemeral synthetic material only. Standards and
implementation references: [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161),
[RFC 5816](https://www.rfc-editor.org/rfc/rfc5816),
[OpenSSL timestamp command](https://docs.openssl.org/3.0/man1/openssl-ts/),
and [OpenSSL CMS command](https://docs.openssl.org/3.0/man1/openssl-cms/).

### Initial direct-CRL verification slice

`experiments/rfc3161_crl_status.py` adds a standalone
`verify_tsa_crl_evidence(...)` path. It requires a prior `VALID` timestamp
result with extracted signer identity, then binds the supplied TSA and issuer
certificates to the exact certificate and issuer digests in that result. It
checks that the issuer is a CA authorized for CRL signing, matches the TSA
certificate's issuer name and Authority Key Identifier, and verifies the CRL
signature under that issuer key.
 The issuer certificate must carry BasicConstraints CA=true and KeyUsage cRLSign=true.

The first supported CRL subset is intentionally narrow: a direct complete
CRL with CRLNumber and Authority Key Identifier, no Issuing Distribution Point,
no delta/freshest-CRL extension, and no CRLDistributionPoints extension on
the TSA certificate (distribution-point scope matching is not implemented).
Unsupported extensions, duplicate target serial entries, indirect entries,
missing required time fields, wrong issuer identity and invalid signatures
fail closed. Tests also cover duplicate target serials, `removeFromCRL`, and
`certificateHold` remaining explicitly indeterminate.

A signed entry whose `revocationDate` is at or before the token's asserted
`genTime` is reported as
`REVOKED_AT_OR_BEFORE_TARGET`, with the result explicitly labelled as an
issuer-signed revocation-time assertion, except for `certificateHold`.
Because a hold can be removed, that reason is reported as
`CERTIFICATE_HOLD_REPORTED_TARGET_STATUS_NOT_ESTABLISHED`; a single CRL
cannot establish that the hold remained in force at the target instant.
`removeFromCRL` is rejected because delta/hold-removal history is not
implemented. Absence from a CRL is only reported
as `NOT_LISTED_AT_CRL_THIS_UPDATE` when the CRL interval covers the target;
it never becomes a positive non-revocation result. Outside that interval,
status remains `NOT_ESTABLISHED`. The CRL's `thisUpdate` is itself an
issuer-signed time assertion, not an independently timestamped clock.

This CRL evaluator is a separate opt-in function; it is not yet wired into
`verify_rfc3161_timestamp(...)`. The timestamp verifier therefore continues
to return `tsa_certificate_revocation: NOT_CHECKED` and
`historical_revocation_assurance: NOT_ESTABLISHED` until an explicit
integration contract is added. The evaluator binds the issuer certificate to
the prior timestamp result but does not independently re-authenticate the
trust root. The OCSP evaluator is limited to the issuer-signed RSA/SHA-256 subset described above. Synthetic integration tests cover
valid direct CRLs, revoked and unlisted serials, issuer mismatch, bad
signatures, missing CRLNumber/AKI, delta and indirect CRL rejection,
partial-reason scope, TSA CRLDistributionPoints, duplicate target serials,
`removeFromCRL`, temporary `certificateHold` and incompatible evidence
intervals.

### Initial issuer-signed OCSP verification slice

`experiments/rfc3161_ocsp_status.py` adds a separate
`verify_tsa_ocsp_evidence(...)` path. It binds the supplied TSA and issuer
certificates to the prior verified timestamp identity, requires the issuer
certificate to authorize digital signatures, and accepts exactly one
`SingleResponse` with a SHA-256 CertID matching issuer-name hash,
issuer-key hash and serial. The responder must be the issuing CA itself;
delegated responder certificates are rejected. The initial signature profile
is RSA/SHA-256 only.

The response signature is verified over the BasicOCSPResponse signed bytes
with the bound issuer key. `producedAt`, `thisUpdate` and `nextUpdate` are
required and checked for a coherent signed interval. If an OCSP request is
supplied, its CertID is checked and any nonce must match exactly. A response
nonce without the corresponding request is rejected. No network retrieval is
performed.

A `good` status is reported only as
`GOOD_AT_OCSP_THIS_UPDATE_ONLY` when the signed interval covers the target;
historical non-revocation remains `NOT_ESTABLISHED`. `unknown` remains
`UNKNOWN`. A signed permanent revocation time at or before the token's
asserted `genTime` can establish a revocation-by-target assertion.
`certificateHold` remains indeterminate because it can be removed. OCSP
`good` is not proof that the certificate was ever issued.

This evaluator, like the CRL evaluator, is opt-in and separate from
`verify_rfc3161_timestamp(...)`; the timestamp result's top-level revocation
fields remain `NOT_CHECKED` / `NOT_ESTABLISHED` until a deliberate integration
contract is added. It binds the issuer certificate to the prior timestamp
result but does not independently re-authenticate the trust root. Synthetic
tests cover issuer-signed good/revoked/unknown responses, exact CertID binding,
RSA signature verification, by-name and by-key responder identity, nonce
match/mismatch/omission, SHA-1 CertID rejection, unsuccessful responses,
delegated-responder rejection, stale/future intervals, revocation after the
target, unsupported extensions and the temporary-hold boundary.

## 9. Remaining integration gates

The first opt-in CRL and OCSP evaluators now exist, but they are not wired into
the primary timestamp-verification result. The following gates remain before
that integration or any top-level positive revocation claim:

1. Promote the draft evidence-envelope schema and policy to a versioned,
   reviewed API contract; JSON structure alone does not authenticate evidence.
2. Preserve the exact signer and issuer certificate identities already
   extracted after successful RFC 3161 verification.
3. Keep the current supported subsets explicit: direct complete CRLs only;
   issuer-signed RSA/SHA-256 OCSP only. Indirect/delta CRLs and delegated OCSP
   responders remain unsupported.
4. Do not infer historical non-revocation from one CRL/OCSP good snapshot.
   A future historical-good claim requires authenticated history or a
   separately specified authoritative issuer assertion.
5. Add remaining adversarial vectors for malformed DER and
   critical-extension edge cases, missing CRL nextUpdate, multiple/ambiguous
   OCSP SingleResponses, and response/request extension combinations not yet
   represented in fixtures. TSA CRLDistributionPoints rejection is now
   covered by a synthetic timestamp-token integration test.
   Delta CRLs and delegated OCSP responders remain rejected rather than
   partially supported.
6. Keep synthetic fixtures self-contained; no production authority, private
   key or live endpoint is required.
7. Keep unsupported and ambiguous outcomes explicitly
   `NOT_ESTABLISHED`; do not convert them to `good`, `false` or a successful
   revocation check.

The next useful step is a focused adversarial test pass over both standalone
evaluators, especially revocation-time ordering and unsupported scope forms.
Only after those tests and a stable policy contract should an optional
CRL/OCSP input be added to the primary timestamp verifier.

## 10. Standards references

- RFC 5280, *Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile*, especially CRL fields, scope, distribution points, indirect CRLs and delta CRLs: https://www.rfc-editor.org/rfc/rfc5280
- RFC 6960, *X.509 Internet Public Key Infrastructure Online Certificate Status Protocol (OCSP)*, especially response time semantics, CertID, responder authorization and status values: https://www.rfc-editor.org/rfc/rfc6960

These references define protocol structures and semantics; they do not by themselves select this project's historical-status policy or authenticate the caller's trust roots.
