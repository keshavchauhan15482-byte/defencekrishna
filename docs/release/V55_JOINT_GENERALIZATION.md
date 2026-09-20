# V55 joint-family generalisation hardening — 20 September 2026

## Result

V55 fixes the deployment-style joint-family regression exposed by the V48 runtime audit without selecting the score on Exploitation or C&C outcomes.

Authoritative GitHub Actions run: `35517835830`  
Evaluated head: `b9a04ac9fc3b5620fdb41d87a7c3bbbb0e48cd78`  
Seeds: `42, 43, 44`  
History: 8 one-minute states  
Forecast horizon: 4 one-minute future states  
Reference gate: recall >= 80% and FPR <= 1% on every seed, with the state model beating persistence.

### Joint exclusion result

Both `exploitation` and `c&c` are excluded together from model fitting, calibration, policy fitting and scorer selection.

| Joint-excluded family | Recall mean ± seed SD | FPR mean ± seed SD | Precision mean | F1 mean | Gate every seed |
|---|---:|---:|---:|---:|---|
| Exploitation | **98.79% ± 1.20 pp** | **0.488% ± 0.042 pp** | **96.62%** | **97.69%** | **PASS 3/3** |
| Command & Control (`c&c`) | **88.53% ± 9.93 pp** | **0.488% ± 0.042 pp** | **96.09%** | **91.98%** | **PASS 3/3** |

Per-seed recall/FPR:

| Seed | Exploitation recall | C&C recall | FPR |
|---:|---:|---:|---:|
| 42 | 97.41% | 82.80% | 0.439% |
| 43 | 99.48% | 100.00% | 0.512% |
| 44 | 99.48% | 82.80% | 0.512% |

Every joint-reserve state model also passed the validation state gate and the test persistence comparison.

## What changed

The V48 joint diagnostic showed the bottleneck was not future-state MSE. The linear known-family logistic transfer head degraded sharply when Exploitation and C&C were removed together.

V55 adds a nonlinear temporal transfer head based on `ExtraTreesClassifier`. Its inputs are network-only history features and deterministic temporal summaries (history flattening, mean, standard deviation, last state, long delta and recent delta). Attack-family labels are never model inputs.

The final score was **not** selected on Exploitation/C&C metrics. It was chosen by pair-holding-out already-exposed development families while permanently masking the two regression families.

Frozen fusion:

- 50% nonlinear temporal transfer evidence
- 25% future-state novelty evidence
- 25% transition-energy evidence
- policy benign-tail budget: 0.25%
- development FPR selection safety margin: 0.75%
- selected candidate: `future_state_novelty25_transition_energy25_nonlinear_temporal_transfer50`

The old linear `known_attack_transfer` receives 0% weight in the selected V55 fusion.

## Selection discipline

Development families used for scorer selection:

- tampering
- lateral movement
- weaponization
- exfiltration
- reconnaissance

Selection simulates multi-family absence by withholding development-family pairs together. Exploitation/C&C exposure is blocked throughout fitting, calibration, policy fitting and scorer selection. `reserve_metrics_used_for_selection = false`.

The V55 candidate search uses a fixed 0.25-weight simplex over six evidence components and policy budgets of 0.1%, 0.25% and 0.5%. The selected scorer maximizes development pair-holdout robustness under the stricter 0.75% development FPR margin before any joint-reserve result is evaluated.

## Component diagnostic

Under the selected 0.25% policy budget, the standalone nonlinear temporal transfer head materially improves transfer relative to the original linear head.

- Exploitation nonlinear-transfer recall by seed: 94.30%, 98.96%, 93.26%; FPR <= 0.073%.
- C&C nonlinear-transfer recall by seed: 62.90%, 80.11%, 20.43%; FPR <= 0.073%.

The frozen fusion is stronger and more stable than that standalone component because it combines nonlinear history transfer with future-state novelty and transition dynamics.

## Claim boundary

This result is a **real three-seed joint-exclusion regression improvement**, but it is not a new untouched-family discovery claim: Exploitation and C&C were exposed in earlier project evidence before V55 was designed. V55 did not use their metrics for scorer selection, which preserves a clean development procedure, but a genuinely independent campaign/family is still required for a new final-holdout generalisation claim.

V55 still does **not** establish:

- a truly undisclosed real-world zero-day;
- publisher-verified pre-compromise lead time;
- supervised MITRE stage-transition accuracy;
- automatic enterprise containment approval.

Unknown-family containment therefore remains shadow/review-only until independent deployment evidence supports enforcement.
