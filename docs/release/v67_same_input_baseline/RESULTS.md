# V67 Same-Input Logistic Regression vs Garuda — Verified Results

Authoritative GitHub Actions run: `35524682867` (`V67 same-input LR vs Garuda benchmark`).

## Scientific contract

- Dataset: independent UNSW-NB15 raw four-shard cyber-range corpus.
- Two support/timestamp-selected unseen-family episodes; episode selection did not use model scores.
- Logistic Regression receives the same observed state-history source (`seq["X"]`) as Garuda, flattened only for LR.
- No future state, attack-family identity, test label, or post-cutoff feature is given to LR.
- LR imputation/scaling is fit on training only.
- LR operating threshold is fit on clean policy-period benign negatives only.
- Garuda fusion remains frozen before UNSW test metrics.
- Same policy false-positive budget: `0.005`.
- Garuda outer seeds: `42, 43, 44`.

## Macro results across Backdoor + Analysis

| Metric | Logistic Regression | Garuda | Garuda − LR |
|---|---:|---:|---:|
| Recall | 57.7910% | 98.6772% | +40.8862 pp |
| FPR | 0.4903% | 0.2871% | -0.2032 pp |
| Precision | 77.7388% | 91.4804% | +13.7416 pp |
| F1 | 64.8467% | 94.6320% | +29.7853 pp |

Garuda result is the macro mean of six family×seed evaluations. It is not presented as a perfect detector; the independent V63 companion audit reports confidence intervals and conservative bounds.

## Logistic Regression exact family results

### Backdoor

- TP=312, FP=46, TN=9314, FN=3
- Recall 99.0476%; 95% Wilson interval [97.2474%, 99.6754%]
- FPR 0.49145%; 95% Wilson interval [0.36861%, 0.65499%]
- Precision 87.1508%
- F1 92.7192%

### Analysis

- TP=25, FP=18, TN=4361, FN=95
- Recall 16.5344%; 95% Wilson interval [10.9552%, 24.1956%]
- FPR 0.48918%; 95% Wilson interval [0.30983%, 0.77112%]
- Precision 68.3060%
- F1 26.6187%

## Claim boundary

This demonstrates measurable improvement of the temporal/world-model system over a same-input Logistic Regression baseline on this held-out public cyber-range protocol. It does **not** prove production zero-day prevention, enterprise readiness, or universal performance on arbitrary networks.
