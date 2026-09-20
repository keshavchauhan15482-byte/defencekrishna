# V72 Prospective CICAPT Attack-Step Onset Lead-Time Audit

Authoritative GitHub Actions run: `35525685873`. Status: **SUCCESS**.

## Claim boundary

This is **attack-step onset** warning evidence against a commit-pinned third-party copy of a CICAPT attack timeline. The provenance file explicitly has `publisher_verified=false`. These numbers must **not** be described as verified successful-compromise lead time, prevention of compromise, or production zero-day performance.

## No-leakage contract

- Residual world model fit on Phase-1 packet+flow state only.
- Phase-2 is excluded from training, normalization, blend selection and threshold selection.
- Warning score uses only the model's predicted future transition magnitude relative to persistence; observed future ground truth is not part of the score.
- Alert threshold is frozen from a late Phase-1 policy segment at a 0.5% reference false-alert budget.
- Timeline events are compared only after the threshold is frozen.
- Three seeds: 42, 43, 44.
- Event lookback: 600 seconds.

## Exact observed results

Across three seeds:

- Mean event-warning recall: **25.3333%**
- SD across seeds: **6.1101 percentage points**
- Mean Phase-2 alert rate: **0.36643%**
- SD alert rate: **0.10866 percentage points**
- Mean of the three per-seed median lead times among warning hits: **269 seconds (4 min 29 sec)**
- World-model validation state gate: PASS 3/3 seeds.

Per seed:

| Seed | Phase-1 policy alert rate | Phase-2 alert rate | Event warning recall | Warning hits | Median lead | Lead range |
|---:|---:|---:|---:|---:|---:|---:|
| 42 | 0.47534% | 0.45609% | 32.0% | 8 | 197 s | 7–529 s |
| 43 | 0.47534% | 0.39761% | 24.0% | 6 | 313 s | 14–529 s |
| 44 | 0.47534% | 0.24559% | 20.0% | 5 | 297 s | 7–529 s |

## Interpretation

The experiment demonstrates that a prediction-only transition score can produce some warnings minutes before independently timestamped attack steps while keeping the Phase-2 alert rate below 0.5% in this bounded experiment. Coverage is **weak**: the mean event-warning recall is only 25.33%. This result is therefore diagnostic evidence, not a release-quality pre-compromise claim. Improving event coverage requires further model/scoring work and a fresh, untouched timeline-bearing campaign for the next independent proof.
