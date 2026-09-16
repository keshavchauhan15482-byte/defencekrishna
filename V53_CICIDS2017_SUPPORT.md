# V53 — CICIDS2017 timestamp-preserving whole-campaign support audit

V53 repairs the blocked CICIDS2017 pre-onset evidence track without weakening the chronology contract.

The common `MachineLearningCSV` mirror used by the earlier V51 attempt removes Timestamp and flow identity fields. V51 correctly refused to reconstruct chronology from row order. V53 instead uses the timestamp-preserving `GeneratedLabelledFlows` / `TrafficLabelling` release variant through a pinned public Parquet mirror.

## Frozen support protocol

- one source traffic-label file = one immutable campaign;
- 10-second windows;
- 8-window observed history = 80 seconds;
- 4-window future horizon = 40 seconds;
- a held-out family reserves the entire campaign containing its evaluation examples;
- all other campaigns provide family-free development support;
- timestamp and labels are chronology/evaluation metadata only, never predictive features;
- missing 10-second buckets are not filled or silently declared benign;
- only physically contiguous 12-window sequences are evaluated.

For every family/campaign pair V53 reports future positives, family-onset positives, clean-history onset positives, clean benign negatives, 10/20/30/40-second support and family-free development support. It also records the first clean-history onset cutoff and a sample of onset timestamps for auditability.

## Training permission gate

A later model experiment is permitted only when the held-out campaign contains at least:

- 20 future-positive sequences;
- 100 clean benign negatives;
- 1 clean-history family onset;
- 1,000 family-free development sequences from other campaigns.

This gate is checked before any model is fit.

## Source boundary

The CI source is the public `bvsam/cic-ids-2017` traffic-label mirror pinned to the original converted-Parquet commit `036f984d251313e814137585af2a65e216c58fe6`. This predates the mirror's later UTC-normalization rewrite.

The later normalized revision `b7e532345512edcd530cb1770dc76636aeb52802` was explicitly rejected for timing evidence after V53 measured a campaign whose `Timestamp` column was already typed `datetime64[us]` but only **37.12%** of rows remained non-null. Dropping the other ~62.88% and calling the remaining timeline complete would create misleading clean-history evidence, so V53 fails closed instead.

The pre-normalization commit is used because it is the commit that originally added the converted CIC TrafficLabelling / GeneratedLabelledFlows Parquets. Every downloaded file is SHA-256 hashed again in the evidence manifest. V53 supports typed datetimes, standard Unix epoch units and mixed valid datetime text, but never reconstructs chronology from row order or invents missing dates.

The publisher CICIDS2017 page independently documents that labeled flows are based on timestamps, endpoint/port/protocol information and attack labels, and gives the attack schedule by day.

## Claim boundary

Passing this support audit proves no model accuracy. A later passing model would establish a clean-history **pre-onset public-dataset proxy** under whole-campaign holdout. It would not by itself prove successful-compromise lead time or detection of an undisclosed production zero-day.
