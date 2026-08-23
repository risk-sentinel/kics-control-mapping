# KICS → NIST 800-53 Rev 5 control mappings

Candidate mappings from KICS queries to Rev 5 controls, the harness that
produces them, and the adjudication trail.

> **These are candidates, not a mapping.** Nothing in `candidates/` should reach
> an SSP, an HDF `tags.nist`, or any compliance artifact until a qualified
> reviewer has adjudicated it into `adjudicated/`.

## Layout

| Path | Contents |
|---|---|
| `candidates/` | 9,055 scored 1:n proposals across 1,811 KICS checks. Input to review. |
| `adjudicated/` | Reviewed mappings. Currently empty. This is what ships. |
| `harness/` | The ranking script. Standard library only, so the ranking reproduces without installing anything. |
| `data/` | The two corpora: 2,048 Rev 5 records (controls plus statement sub-parts) and 1,811 KICS check metadata records. |

## Why this exists

Converter `tags.nist` output is currently derived from a CWE→NIST lookup that
resolves only 30 of the 102 CWEs KICS uses — **52% of queries by volume**. The
remainder falls through to `SA-11, RA-5`, which describe how a finding was
produced rather than what it violates.

The Checkov and AWS Config mappers in `mitre/heimdall2` solve this with a
reviewed per-rule table shipped as data, which is also what lets those tables
carry control enhancements (`CKV2_ADO_1 → CM-3(2), CM-5(1)`). This repo produces
the equivalent table for KICS.

KICS makes that tractable: it ships its full query catalog as data — 1,811
`metadata.json` files under `/app/bin/assets/queries/` in the distributed image
— so every query is known ahead of any scan.

Consumers: `mitre/hdf-libs#240` and `mitre/heimdall2#8573` both resolve
table-first and fall back to CWE, recording which tier answered in a
`nistMapping` tag. Process: `mitre/hdf-libs#239`.

## Method

BM25 over control `statement` + `assessment-objective` + `guidance`, with
`title` weighted ×4, plus a KICS-category → NIST-family prior (boost 1.6,
penalty 0.25).

Two design decisions came from observed failures, not theory:

**Title weighting ×4.** Many Rev 5 controls state themselves almost entirely in
organization-defined parameters — SC-28 reads *"Protect the {{ODP}} of the
following information at rest: {{ODP}}"*. Strip the parameters and no matchable
text remains, so the title carries the signal.

**The family prior.** Purely lexical ranking matched *"Cloud Storage Bucket Is
Publicly Accessible"* to **PE-3 Physical Access Control** at 0.93. An explicit,
arguable prior beats a tuned similarity threshold: a reviewer can disagree with
a prior.

## Read before trusting any number

**Scores are relative, not confidence.** Each candidate's `score` is normalised
against the best candidate *for that check*, so **every rank-1 candidate scores
exactly 1.0**. A score threshold cannot be used as an acceptance rule. Use
`raw` (unnormalised BM25) and the rank-1/rank-2 margin if you need an absolute
signal — both are in the JSON.

**`quality-by-category` style metrics are circular.** Any measure of "how often
the top candidate lands in the expected family" is measuring the family prior
working, not the mapping being correct.

**Encryption is known-weak.** Encryption-at-rest checks rank `SI-19.4` (Removal,
Masking, Encryption, Hashing, or Replacement) and `SC-12.x` (key management)
above `SC-28` (Protection of Information at Rest), which is usually correct.
`SI-19.4`'s title literally contains the word "Encryption"; lexical ranking
cannot resolve that. **Expect to re-map most of that category by hand — 207
checks.**

Spot-checked as reasonable: Backup → `CP-9`, Secret Management → `IA-5.18`,
public-access → `AC-22`, Observability → `AU-*`. Reasonable is not correct.

## Provenance

- Catalog: NIST SP 800-53 Rev 5 (OSCAL), pinned at `78650f02ad9321bb7b817846f8fbd4f2bcd620de`
- Scanner: KICS, catalog extracted from `checkmarx/kics:latest`

Both sides must stay pinned. Check semantics drift between scanner releases and
control text changes between catalog releases; a mapping is valid only for the
pair it was reviewed against.

## Reproducing

```bash
python3 harness/score_mappings.py data/rev5-corpus.json data/kics-checks.json candidates/kics-control-candidates.v1.json
```
