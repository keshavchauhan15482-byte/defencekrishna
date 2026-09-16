# V49 frozen-score reserved unseen-family results

V49 preserves the merged ToN-IoT V48 track and records the separate X-IIoTID reserve-family experiment. The warning-score design was frozen on five already-exposed V47 pseudo-unseen families before C&C and Exploitation were evaluated.

This is public-dataset family-disjoint evidence, not proof of a real undisclosed zero-day or verified pre-compromise lead time.

## Frozen candidates

- Pure world: `world_delta_future`
- Hybrid: `hybrid_log50_delta50`
- Baseline: `logistic_only`

No reserve-family positive metric was used to select these choices.

## C&C reserve

Support: **186 positives + 1,366 benign negatives**. State forecasting beats persistence on validation and reserve evaluation for all three seeds.

| Score | Recall mean ± SD | FPR mean ± SD | All-seed gate |
|---|---:|---:|---|
| `world_delta_future` | 32.80% ± 18.66 | **0.561% ± 0.112** | fail recall |
| `hybrid_log50_delta50` | **99.82% ± 0.31** | 2.001% ± 0.042 | fail FPR |
| `logistic_only` | 96.77% ± 0.00 | 2.050% ± 0.00 | fail FPR |

Hybrid per seed:

- seed 42: 99.46% recall / 2.050% FPR
- seed 43: 100.00% / 1.977%
- seed 44: 100.00% / 1.977%

## Exploitation reserve

Support: **193 positives + 1,366 benign negatives**. State forecasting beats persistence on validation and reserve evaluation for all three seeds.

| Score | Recall mean ± SD | FPR mean ± SD | All-seed gate |
|---|---:|---:|---|
| `world_delta_future` | 0.86% ± 0.60 | **0.439% ± 0.073** | fail recall |
| `hybrid_log50_delta50` | **99.14% ± 0.60** | **1.122% ± 0.184** | fail FPR consistency |
| `logistic_only` | 98.45% ± 0.00 | 1.903% ± 0.00 | fail FPR |

Hybrid per seed:

- seed 42: **98.45% recall / 0.952% FPR**
- seed 43: 99.48% / 1.098%
- seed 44: 99.48% / 1.318%

Seed 42 passes the numerical FPR<=1% / recall>=80% target, but V49 requires consistent three-seed passage, so Exploitation is not declared passed.

## State-transition evidence

Every seed beats persistence for both reserve families. Examples:

- C&C seed 42: test state MSE 0.33475 vs persistence 0.54829.
- Exploitation seed 42: test state MSE 0.29924 vs persistence 0.55627.

This supports transferable state dynamics; the remaining bottleneck is alert/readout operating-point stability.

## Interpretation

V49 strengthens the unseen-family evidence without post-hoc reserve tuning:

1. state dynamics transfer to both newly evaluated reserve families;
2. the frozen hybrid materially improves Exploitation FPR versus logistic-only while preserving/increasing recall;
3. C&C retains near-perfect recall but remains above the 1% FPR target;
4. pure world novelty stays low-FPR but low-recall;
5. C&C and Exploitation are now exposed diagnostics and cannot be reused as a fresh holdout.

The next independent unseen/zero-day-like evidence must come from a new campaign/family/dataset with adequate positives and clean benign support. The already merged ToN-IoT V48 audit found no future-positive family support in its final chronological tail, so it correctly produces no success metric.

## Reproduction

- Latest-main V49 reserved-family workflow: GitHub Actions run `35092549633`, completed successfully.
- V49 evidence artifact: `v49-reserved-unseen-evidence`, SHA-256 digest `8103d39e6ef5086da276623603c69773ebbc3ca8568d85f4d3fc338ec1d43147`.
- Full Krishna integration regression on the same PR head: run `35092549647`, completed successfully.

The latest-main rerun reproduced the same frozen candidates and the same reserve metrics reported above.
