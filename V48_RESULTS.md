# V48 frozen-score reserved unseen-family results

V48 freezes warning-score design on the five already-exposed V47 pseudo-unseen families, then evaluates **C&C** and **Exploitation** only after the pure-world and hybrid candidates are selected. These are public-dataset family-disjoint results, not proof of a real undisclosed zero-day or verified pre-compromise lead time.

## Frozen selection

Development pseudo-unseen families:

- Tampering
- Lateral Movement
- Weaponization
- Exfiltration
- Reconnaissance

Previously unscored reserve families before V48:

- C&C
- Exploitation

The fixed candidate-selection rule chose:

- **Pure world:** `world_delta_future` — equal mixture of predicted-future benign-tail surprise and predicted change-from-persistence surprise.
- **Hybrid:** `hybrid_log50_delta50` — equal mixture of known-attack logistic benign-tail surprise and world predicted-change surprise.
- **Baseline:** `logistic_only`.

No reserve-family positive metric was used to select these choices.

## Development selection behavior

The selected pure-world score kept mean FPR within 1% on four of five exposed development families but had low recall. The selected hybrid was the only hybrid candidate to produce a complete FPR<=1% / recall>=80% development-family gate, but it did not satisfy the gate on all development families.

This is why both pure-world and hybrid candidates were carried into reserve evaluation instead of silently promoting only the more favorable one.

## Reserve family: C&C

Support: **186 positives + 1,366 benign negatives**. State forecasting beats persistence on validation and reserve evaluation for all three seeds.

| Score | Recall mean ± SD | FPR mean ± SD | All-seed release gate |
|---|---:|---:|---|
| `world_delta_future` | 32.80% ± 18.66 | **0.561% ± 0.112** | fail recall |
| `hybrid_log50_delta50` | **99.82% ± 0.31** | 2.001% ± 0.042 | fail FPR |
| `logistic_only` | 96.77% ± 0.00 | 2.050% ± 0.00 | fail FPR |

Per-seed hybrid recall/FPR:

- seed 42: 99.46% recall / 2.050% FPR
- seed 43: 100.00% / 1.977%
- seed 44: 100.00% / 1.977%

The hybrid preserves almost all unseen C&C recall and slightly reduces FPR versus logistic-only, but remains above the <=1% target.

## Reserve family: Exploitation

Support: **193 positives + 1,366 benign negatives**. State forecasting beats persistence on validation and reserve evaluation for all three seeds.

| Score | Recall mean ± SD | FPR mean ± SD | All-seed release gate |
|---|---:|---:|---|
| `world_delta_future` | 0.86% ± 0.60 | **0.439% ± 0.073** | fail recall |
| `hybrid_log50_delta50` | **99.14% ± 0.60** | **1.122% ± 0.184** | fail FPR consistency |
| `logistic_only` | 98.45% ± 0.00 | 1.903% ± 0.00 | fail FPR |

Per-seed hybrid recall/FPR:

- seed 42: **98.45% recall / 0.952% FPR** — passes the numerical target for this seed
- seed 43: 99.48% / 1.098%
- seed 44: 99.48% / 1.318%

This is the strongest family-disjoint result so far: the frozen hybrid cuts mean FPR from 1.90% to 1.12% while increasing recall slightly. However the protocol requires the gate to hold consistently, so **Exploitation is not declared passed**.

## State-transition result

For both reserve families, every seed's learned state model beats persistence on family-free validation and on the reserve evaluation set. This strengthens the conclusion that the remaining bottleneck is mainly alert/readout calibration and cross-family operating-point stability, not absence of transferable state dynamics.

Examples:

- C&C seed 42 test state MSE: 0.33475 vs persistence 0.54829.
- Exploitation seed 42 test state MSE: 0.29924 vs persistence 0.55627.

## What V48 establishes

V48 provides stronger evidence than V47 without reusing exposed families as a fresh holdout:

1. learned network-state dynamics transfer to two newly evaluated attack families;
2. a frozen world+transfer hybrid materially improves the unseen-family FPR/recall tradeoff over logistic-only for Exploitation;
3. one Exploitation seed crosses FPR<=1% and recall>=80%, but the three-seed consistency gate does not pass;
4. C&C remains a false-positive-control problem despite near-perfect recall;
5. pure-world novelty remains too low-recall to serve as the sole attack-warning score.

## Evidence boundary and next protocol

C&C and Exploitation are now exposed diagnostics. Future scoring changes may use them as development evidence, but they cannot be renamed as a new untouched holdout.

A stronger unseen/zero-day-like claim now requires a **new dataset or newly reserved attack families/campaigns**. The next protocol should freeze the V48 scoring family before inspecting those new outcomes.

GitHub Actions run `35091414159` completed V48 tests, public X-IIoTID download, development score selection, three-seed reserve evaluation, summary and evidence artifact successfully. Full Krishna regression run `35091414128` also passed.
