# V53 — CICIDS2017 timestamp-preserving whole-campaign support audit

V53 repairs the blocked CICIDS2017 pre-onset evidence track without weakening the chronology contract.

The common `MachineLearningCSV` release used by the earlier V51 attempt removes Timestamp and flow-identity fields. V51 correctly refused to reconstruct chronology from row order. V53 now uses the original-distribution `GeneratedLabelledFlows.zip` / TrafficLabelling CSV variant instead of converted Parquets.

## Frozen support protocol

- one source traffic-label CSV = one immutable campaign;
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

The publisher CICIDS2017 page documents that the dataset includes labeled flows in `GeneratedLabelledFlows.zip`, and that flow labels are based on timestamp, source/destination identity, ports, protocol and attack information.

V53 downloads only `GeneratedLabelledFlows.zip` from the public `bencorn/CICIDS2017` Hugging Face repository, which describes itself as an **unofficial mirror of the original CIC distribution**. CI resolves the mirror's `main` revision to an exact repository SHA before downloading, records that resolved SHA in the evidence manifest, SHA-256 hashes the archive, safely extracts exactly the eight expected CIC campaign CSVs by basename, and SHA-256 hashes every extracted CSV. Once a successful support run resolves the mirror revision, that exact SHA is pinned for the authoritative rerun.

Two converted-Parquet routes were explicitly rejected for timing evidence. Both the later normalized revision and the earlier converted-Parquet commit of `bvsam/cic-ids-2017` left only **37.12%** non-null typed timestamps in at least one campaign. Dropping the other ~62.88% and treating the remaining rows as a complete timeline would create misleading clean-history evidence, so those conversions are not used for V53 timing claims.

V53 also validates parsed timestamps against the independently known campaign date encoded by the CICIDS2017 weekday filename: Monday 2017-07-03 through Friday 2017-07-07. Ambiguous day/month text is accepted only when one valid interpretation matches the expected campaign date on at least 95% of parsed rows. There is no row-order, synthetic-date, gap-fill or forward-fill fallback.

## Claim boundary

Passing this support audit proves no model accuracy. A later passing model would establish a clean-history **pre-onset public-dataset proxy** under whole-campaign holdout. It would not by itself prove successful-compromise lead time or detection of an undisclosed production zero-day.
