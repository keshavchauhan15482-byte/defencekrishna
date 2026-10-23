# V51 — CIC-IDS2017 whole-campaign unseen-family support audit

V51 searches for the evaluation structure that the SIH forecasting claim actually needs: a held-out attack family on a whole unseen campaign, plus clean benign history immediately before future malicious activity.

## Why CIC-IDS2017

Unlike WUSTL/ToN-IoT final tails that turned out to be attack-free, CIC-IDS2017 is organized into timestamped attack-day captures. The public dataset contains benign traffic mixed with distinct attack campaigns including FTP/SSH brute force, several DoS variants, Heartbleed, Web attacks, Infiltration, Botnet, PortScan and DDoS.

## Frozen support protocol

- input: labeled CICFlowMeter CSVs, one CSV = one immutable campaign;
- window: 10 seconds;
- observed history: 8 windows = 80 seconds;
- future horizon: 4 windows = 40 seconds;
- held-out family evaluation reserves its entire source CSV/campaign;
- all other campaign CSVs are development support;
- timestamp and labels are split/evaluation truth only, never model inputs;
- gaps are not filled or relabeled benign; a sequence must contain 12 physically contiguous 10-second buckets.

For each family/campaign pair V51 reports:

- all future-positive sequences;
- family-onset positives where the family is absent from observed history;
- clean-history onset positives where the complete 80-second history contains no attack-labelled traffic;
- clean benign negatives in the same held-out campaign;
- family-free sequence support across all other campaigns;
- 10/20/30/40-second positive support.

A pair permits a later fresh model experiment only if it has >=20 future positives, >=100 clean benign negatives, >=1 clean-history onset positive and >=1000 family-free development sequences.

## Claim boundary

This audit itself proves no model performance. CIC-IDS2017 attack labels are known public attack campaigns, so a later passing result would be a family/campaign-disjoint zero-day-like simulation, not proof of detecting an undisclosed real-world zero-day or verified successful-compromise lead time.
