# V47 unseen-family benchmark results

This report records the executed X-IIoTID family-disjoint experiment. It is a controlled **unseen-family / zero-supervised-exposure** benchmark, not proof of a real undisclosed zero-day or verified pre-compromise lead time.

## Executed protocol

- X-IIoTID source: 820,834 rows / 68 columns / SHA-256 `7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0`.
- Strict network-only feature allow-list: 21 raw traffic fields.
- 8-minute observed history, 4-minute future trajectory.
- Seeds 42, 43, 44; no best-seed promotion.
- Held-out family removed from training, state validation, calibration and policy fitting.
- Five families selected by support only: Tampering, Lateral Movement, Weaponization, Exfiltration, Reconnaissance.
- Test benign support: 1,366 sequences for every selected family.

Strict chronological pre-onset support was zero for every family in the final tail, so X-IIoTID cannot establish verified pre-compromise lead time under that split.

## World warning result

| Held-out family | Positives | State gate | Mean world recall | Mean FPR | Gate |
|---|---:|---|---:|---:|---|
| Tampering | 1,876 | pass | 0.00% | 3.34% | fail |
| Lateral Movement | 1,598 | pass | 32.67% | 0.317% | fail recall |
| Weaponization | 557 | pass | 12.15% | 0.317% | fail recall |
| Exfiltration | 471 | pass | 0.00% | 0.390% | fail recall |
| Reconnaissance | 364 | fails persistence | 16.85% | 0.415% | fail state + recall |

## Logistic transfer baseline

| Held-out family | Recall | FPR |
|---|---:|---:|
| Tampering | 87.42% | 3.37% |
| Lateral Movement | 57.45% | 1.39% |
| Weaponization | 98.38% | 2.78% |
| Exfiltration | 99.79% | 2.05% |
| Reconnaissance | 40.66% | 1.61% |

V47 showed that state-transition learning often transfers, but the original world-only warning score is too conservative while the known-family discriminative signal exceeds the 1% FPR budget. These outcomes are development evidence and are not fresh holdouts after V47.

Latest V47 workflow run `35089717060` and full Krishna integration run `35089717012` completed successfully.
