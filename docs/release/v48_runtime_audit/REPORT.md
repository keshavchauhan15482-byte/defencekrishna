# V48 runtime and joint-reserve audit — 20 September 2026

Fresh local CPU reproduction using fixed documented V48 weights (75% logistic transfer, 25% transition energy) and policy budget 0.25%. No reserve-based score selection was performed. These public families were previously exposed; this is a reproducibility/deployment diagnostic, not a newly untouched holdout.

| Protocol | Family | Recall mean ± seed SD | FPR mean ± seed SD | F1 | Test state MSE / persistence |
|---|---|---:|---:|---:|---:|
| Separate family folds | exploitation | 92.06% ± 0.30 pp | 0.390% ± 0.042 pp | 94.50% | 0.300181 / 0.556270 |
| Separate family folds | c&c | 87.81% ± 2.71 pp | 0.366% ± 0.000 pp | 92.18% | 0.328345 / 0.548292 |
| Joint reserve | exploitation | 71.16% ± 0.30 pp | 0.293% ± 0.000 pp | 82.15% | 0.303802 / 0.558597 |
| Joint reserve | c&c | 31.54% ± 0.82 pp | 0.293% ± 0.000 pp | 47.18% | 0.324706 / 0.538767 |

All six reference and six joint-reserve exports passed reload parity on state predictions, evidence scores and alert decisions. The joint models use the same fitting masks across both family evaluations. All seeds beat test persistence; both joint-reserve family recall gates fail. Seed SD is not a campaign-level confidence interval.

## What was fixed
- Portable no-pickle model export includes fitted world-model weights, imputation, scaling, logistic coefficients, benign-tail references and thresholds.
- Runtime validates artifact checksums, dependency versions, feature ordering and 60-second window contract.
- All-seed gate rejects missing seeds rather than checking only successful runs.
- Validation and test persistence checks are now reported separately, including state MSE by horizon.
- Offline dashboard has an explicit V48 shadow CSV option. It requires installed joint models for seeds 42/43/44, rejects family-specific routing, and never translates tail evidence into an attack percentage.
- CSV model input ignores attack labels. Driving features include exact logistic-head contributions and per-feature transition energy; these are not causal attribution.
- Unknown containment remains disabled. No deployment gate was weakened to improve headline numbers.

## Validation
- Garuda regression: see test_results.txt. Proxy and integrity checks passed; V11 enforcement and local engine/console smoke passed.
- Real HTTP upload: 200, 32 forecasts from the first 10,000 source rows after explicitly excluding four rows without valid timestamps. This subset is an integration fixture, not a benchmark or complete traffic capture.
- Three-seed reports, fitted artifacts and source hash are included in the evidence package. Raw source data is not included.

## Remaining evidence gaps
- Clean-onset future-positive count is zero in both evaluated families; verified advance-warning recall and lead time cannot be inferred from these results.
- Recovered CICAPT annotation audit has 58 attack-step records but no explicit compromise timestamp. Publisher verification remains false; this is development-grade annotation evidence.
- Supervised five-stage accuracy has not been established by this work.
- V48 is an LSTM/direct multi-horizon + logistic fusion model. This result is not a GNN result or a 10-second autoregressive graph-model result.
- End-to-end shadow CSV inference is implemented; production telemetry and automatic unknown containment are not approved.

## Next model experiment
Use only exposed development families for multi-family exclusion training and scorer selection. Compare transition residual/trajectory signals and robust risk training under the same low-FPR policy; preserve these joint-reserve failures as development evidence. Reserve a genuinely independent campaign for final evaluation. Architecture or threshold changes must not be chosen against a final holdout. Obtain aligned clean pre-attack histories and independently evidenced onset/compromise labels before claiming pre-compromise forecasting.

## Run
```bash
python -m garuda_v3.v48_joint_reserve --csv /path/to/XIIoTID.csv --frozen-config docs/release/v48_runtime_audit/frozen_reference_config.json --output /new/output/folder --epochs 12 --include-reference
GARUDA_V48_RUNTIME_DIR=/path/to/evidence/runtime python start_local.py
```
Open the console on port 8091 and select “V48 minute-state CSV · shadow only”. Matching raw X-IIoTID columns and eight contiguous one-minute host states are required.
