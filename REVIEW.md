# Adjudication process

Candidates become mappings only by review. This is the process, and the reason
the repo exists rather than a spreadsheet: every decision gets a PR, an author
and a date.

## How to review

1. **Work `candidates/kics-control-candidates-review.csv`, sorted by
   `kics_category`.** Adjudicating forty checks while holding one control family
   in mind is far faster than forty context switches, and category is the
   strongest signal in this data — Backup was uniformly good, Encryption
   uniformly wrong.
2. **Fill `DECISION`, `REVIEWER`, `NOTES`.** Accept, reject, or amend with a
   different control.
3. **A check may map to several controls.** The 1:n shape is deliberate. Forcing
   1:1 is what put 15 of the CWE Top 25 onto `SI-10` in the CWE table this
   replaces.
4. **Record rejections with a reason.** A rejected candidate with rationale stops
   the next harness run re-proposing it; a silently deleted row does not.
5. **Open a PR per category.** The diff is the audit trail.

## On score thresholds

An auto-accept tier is desirable and not yet earned. The scores in
`candidates/` are normalised per check, so every rank-1 candidate is 1.0 and no
threshold distinguishes anything. Testing absolute strength plus rank-1/rank-2
margin still put 40 Encryption checks — a category known to be wrong — into the
strictest tier.

The failure mode is not low confidence, it is confident error.

**To earn a threshold:** adjudicate 50–100 checks across the range, then measure
which signal actually separates accepted from rejected and set the cut from that
evidence. Until then, treat any tiering as a review *order*, not an acceptance
rule.

## What ships

`adjudicated/kics-control-mapping.v1.json` is the only file a converter should
consume. It carries, per check: the accepted controls, the reviewer, the
decision date, and the catalog and scanner versions the decision was made
against.
