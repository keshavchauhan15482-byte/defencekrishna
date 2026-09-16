# V12 — Forecast-to-risk value test and readiness failure

V12 performed 27 supervised logistic risk-readout fits on existing labelled flow
windows: 3 representations × 3 seeds × 3 horizons (1/2/4 minutes). The LSTM and
GNN state forecasters were frozen V10 checkpoints, not retrained world models.
No new dataset, invented incident timestamp or fabricated stage label was added.

**Result: the attack-risk release gate failed. None of the 27 readouts is
approved for enforcement. A 9/10 predictive-defence claim is not supported.**

## Experiment

Representations:

1. Observed history alone: eight windows of pooled host features.
2. The same history plus four predicted states from a frozen LSTM.
3. The same history plus four predicted states from a frozen GNN+LSTM.

Each logistic readout uses training-only StandardScaler, C=1, balanced training
class weights and max_iter=2000. Seeds are 42,43,44. The target is any known
malicious-flow window within the next 1/2/4 minutes, not compromise probability.
Unknown targets are excluded; observed traffic with unknown labels is never
silently treated as benign. Saved weights use NPZ, not executable pickle.

Development captures are the existing 22 Feb, 23 Feb and 2 Mar IDS2018 graphs.
For every capture: first 70% risk training, 70–85% calibration, final 15% policy
selection, with 12-window embargo at each boundary. Examples require eight
history plus four future contiguous windows; stride is 2. No raw window overlaps
between these risk-training/calibration/policy/test partitions. V10 state models
had used their development-validation traffic for state-checkpoint selection;
these are not newly untouched validation captures for the whole model pipeline.

Reused diagnostic test captures: DoS 15 Feb and infiltration 1 Mar. Neither was
used for the V12 readout fitting or its threshold selection. Both had already
been evaluated in earlier versions; this is not fresh independent validation.
DoS test has 68 examples before target filtering; infiltration has 11. For the
four-minute target, 8 DoS targets remain unknown and are excluded.

## Four-minute DoS numbers

Three-seed averages at the fixed, predeclared **0.5 diagnostic threshold**.
Scores are uncalibrated because calibration support was insufficient. These are
NOT approved operating-point metrics. Sample SD describes seed variation, not
independent campaign confidence. The test has 32 known benign and 28 known
malicious targets. Overlapping windows are correlated.

| Risk representation | FPR mean ± SD | Recall mean ± SD | F1 mean ± SD |
|---|---:|---:|---:|
| History only | 96.88% ± 0.00 pp | 96.43% ± 0.00 pp | 0.6279 ± 0.0000 |
| History + LSTM state forecasts | 85.42% ± 19.85 pp | 92.86% ± 12.37 pp | 0.6412 ± 0.0968 |
| History + GNN state forecasts | 96.88% ± 0.00 pp | 88.10% ± 12.54 pp | 0.5880 ± 0.0597 |

LSTM-derived features improved average FPR by 11.46 percentage points relative
to history alone, but FPR remains unacceptable and seed variation is large. GNN
features did not improve this diagnostic. The baseline seed runs are identical
because the representation and deterministic solver are unchanged; repetition
does not make them independent evidence.

Infiltration's 11 known test cases are all positive. At the same diagnostic
threshold, recall is 72.73% (history), 75.76% (LSTM features), and 78.79% (GNN
features). **FPR is undefined** because that capture has no known negative test
cases. Do not report its perfect precision as proof of safe deployment.

All 1-, 2- and 4-minute metrics, per-seed confusion matrices, Brier scores,
probabilities and checkpoints are included in `datasets/v12/summary.json` and
`garuda_v3/artifacts/v12/*/metrics.json`.

## Why operating thresholds remain disabled

Four-minute target counts, shown as benign / malicious / unknown:

| Partition | Counts |
|---|---:|
| Training | 247 / 137 / 88 |
| Calibration | 61 / 11 / 1 |
| Policy selection | 77 / 0 / 1 |
| Combined diagnostic test | 32 / 39 / 8 |

Calibration fails the existing minimum 20 cases per class. Policy selection has
zero attack-positive cases, so it cannot validate useful recall. All tested
horizons fail readiness. At the withheld policy, no attack alert is issued;
zero resulting false positives must not be sold as a successful detector.
There are **zero clean-history future-positive test examples** in either test
capture for this setup, so pre-compromise warning success cannot be measured.

The script now performs a readiness preflight. By default it refuses fitting
with insufficient calibration/policy support. `--diagnostic-only` is required to
reproduce these deliberately non-actionable exploratory fits. This guard was
added after the first diagnostic run revealed the missing class support; it
does not change that run's fitted parameters or metrics. Existing output folders
are never overwritten.

## Code and checks

- Added reproducible forecast-feature risk-readout experiment and frozen config.
- Added disjoint calibration/policy blocks and machine-readable readiness counts.
- Added a default refusal to train actionable candidates from unsupported blocks.
- Added tests for no shared raw windows, missing policy classes, unknown-label
  exclusion and disabled-policy recall reporting.
- Retained all V11 protection fixes and the existing default defence model.
- No trained supervised MITRE head, verified compromise lead time, automatic
  forecast-to-block integration or production validation is claimed.

## Reproduce

From the project root:

```bash
# First inspect the readiness gate. It intentionally fails on this dataset split.
python -m garuda_v3.v12_risk_experiment

# To reproduce exploratory fits after archiving the existing artifacts/v12 folder:
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.v12_risk_experiment --diagnostic-only
python -m unittest discover -s garuda_v3/tests
npm run test:v11
```

The first run used the same frozen numeric config before the explicit CLI
readiness guard was added. The results are retained, not replaced by a more
favourable post-hoc threshold. V10 state-MSE improvements remain valid for their
stated reused-holdout scope, but they do not establish attack-risk quality.

## What unblocks the next valid experiment

1. Obtain the original CICAPT Attack_info.csv / Caldera reports and verify clock,
   host/PID, event outcome and negative-label coverage against the capture.
2. If annotations/prehistory are insufficient, collect independent isolated lab
   runs with at least eight complete observed minutes before relevant events,
   enough benign and attack cases in each development partition, and explicit
   success/failure outcome logs. Never invent missing prehistory.
3. Freeze entire unseen runs before fitting. Reserve calibration and policy runs
   with both classes, and an independent untouched final evaluation.
4. Train progression targets only where the timeline supports them. Measure
   incident-level recall and lead time, benign alert burden, per-stage results
   and actual forecast-triggered upstream prevention separately.

The currently missing verified timeline cannot be supplied by additional epochs,
threshold manipulation or reporting only the best seed. This version provides
measured negative evidence and concrete data requirements, not a 9/10 claim.

## Verification results

69 Python tests passed. V11 regression also passed: 15 strict control checks and 12 actual loopback HTTP checks. All 27 V12 readout reports were inspected: no actionable readout, no automatic containment approval, no reported compromise lead time or stage accuracy.
