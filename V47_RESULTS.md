# V47 unseen-family benchmark results

This report records the executed X-IIoTID family-disjoint experiment. It is a controlled **unseen-family / zero-supervised-exposure** benchmark, not proof of a real undisclosed zero-day or verified pre-compromise lead time.

## Executed protocol

- Public X-IIoTID source: 820,834 rows / 68 columns / SHA-256 `7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0`.
- Strict network-only numeric feature allow-list: 21 raw traffic fields; process/resource/OSSEC/login/class fields excluded.
- 8-minute observed history, 4-minute future trajectory.
- Seeds 42, 43, 44; no best-seed promotion.
- Held-out family removed from training, state validation, calibration and policy fitting.
- Five families selected by support only: Tampering, Lateral Movement, Weaponization, Exfiltration, Reconnaissance.
- Test benign support: 1,366 sequences for every selected family.

The strict chronological pre-onset audit found zero eligible held-out-family future positives in the final chronological tail for every family, so X-IIoTID cannot establish verified pre-compromise lead time under that split.

## World forecast / open-set warning

| Held-out family | Positives | Validation state gate | Mean world recall ± SD | Mean FPR ± SD | Gate |
|---|---:|---|---:|---:|---|
| Tampering | 1,876 | pass | 0.00% ± 0.00 | 3.34% ± 1.90 | fail |
| Lateral Movement | 1,598 | pass | 32.67% ± 0.49 | 0.317% ± 0.042 | fail recall |
| Weaponization | 557 | pass | 12.15% ± 6.21 | 0.317% ± 0.042 | fail recall |
| Exfiltration | 471 | pass | 0.00% ± 0.00 | 0.390% ± 0.085 | fail recall |
| Reconnaissance | 364 | fails persistence | 16.85% ± 5.87 | 0.415% ± 0.112 | fail state + recall |

No held-out family passes FPR <=1% and recall >=80% across all seeds.

## Logistic transfer baseline

| Held-out family | Recall | FPR |
|---|---:|---:|
| Tampering | 87.42% | 3.37% |
| Lateral Movement | 57.45% | 1.39% |
| Weaponization | 98.38% | 2.78% |
| Exfiltration | 99.79% | 2.05% |
| Reconnaissance | 40.66% | 1.61% |

The conventional discriminative signal transfers to several unseen families, but exceeds the <=1% FPR budget on every selected family.

## Main finding

The V47 result separates two problems: state-transition learning often transfers, but the original predicted-future benign-manifold score is too conservative to convert that state forecast into useful unseen-family warnings. These five outcomes are now exposed development evidence and must not be relabelled as a fresh holdout after score tuning.

Latest V47 workflow run `35089717060` and full Krishna integration run `35089717012` both completed successfully.
