# V47 unseen-family benchmark results

This report records the executed X-IIoTID family-disjoint experiment. It is a controlled **unseen-family / zero-supervised-exposure** benchmark, not proof of a real undisclosed zero-day or verified pre-compromise lead time.

## Executed protocol

- Public X-IIoTID source downloaded independently in GitHub Actions.
- Strict network-only numeric feature allow-list: 21 raw traffic fields; process/resource/OSSEC/login/class fields excluded.
- 8-minute observed history, 4-minute future trajectory.
- Seeds 42, 43, 44; no best-seed promotion.
- Held-out family removed from training, state validation, calibration and policy fitting.
- Benign-only policy threshold targets <=1% empirical FPR on the development policy block.
- Five families selected by support count only: Tampering, Lateral Movement, Weaponization, Exfiltration, Reconnaissance.
- Test benign support: 1,366 sequences for every selected family.

The strict chronological pre-onset audit found **zero eligible held-out-family future positives in the final chronological test tail for every family**. Therefore X-IIoTID cannot establish the SIH pre-compromise/clean-history warning claim under this split. The leave-one-family-out benchmark below measures family-disjoint generalisation, not advance warning.

## World-state forecasting

For four of five held-out families, all three world-model seeds beat persistence on family-free validation and the held-out-family evaluation set. Reconnaissance fails the persistence gate.

| Held-out family | Positive support | State gate | Mean world anomaly recall | Mean benign FPR | Unseen-family gate |
|---|---:|---|---:|---:|---|
| Tampering | 1,876 | pass all seeds | 0.00% | 3.20% | fail |
| Lateral Movement | 1,598 | pass all seeds | 32.19% | **0.32%** | fail recall |
| Weaponization | 557 | pass all seeds | 11.19% | **0.32%** | fail recall |
| Exfiltration | 471 | pass all seeds | 0.00% | **0.39%** | fail recall |
| Reconnaissance | 364 | **fail all seeds** | 16.67% | **0.41%** | fail state + recall |

The open-set world-forecast score is conservative on four families but misses too many unseen attacks. No held-out family passes the required FPR <=1% and recall >=80% gate across all seeds.

## Known-family discriminative baseline on unseen families

The logistic history baseline was trained without the held-out family and evaluated on the exact same unseen-family positives and benign negatives.

| Held-out family | Recall | Benign FPR |
|---|---:|---:|
| Tampering | 87.42% | 3.37% |
| Lateral Movement | 57.45% | 1.39% |
| Weaponization | **98.38%** | 2.78% |
| Exfiltration | **99.79%** | 2.05% |
| Reconnaissance | 40.66% | 1.61% |

This shows useful cross-family transfer for several attack families, but the false-positive rate does not meet the <=1% release target. It must not be presented as a zero-day success.

## Clean-history / pre-onset support

Leave-one-family-out clean-history onset support was:

- Tampering: 0
- Lateral Movement: 0
- Weaponization: 6
- Exfiltration: 0
- Reconnaissance: 0

The six Weaponization clean-history cases were all missed by the world-anomaly score. The strict chronological pre-onset benchmark selected no family because the final test tail contains zero supported future onsets. Verified compromise lead time remains unavailable.

## Main finding

V47 answers an important question honestly:

- Garuda's learned state dynamics can transfer beyond the held-out family for several families.
- The current **benign future-trajectory anomaly score is not sufficient** for unseen-family attack warning.
- A discriminative known-attack model transfers surprisingly well to Weaponization/Exfiltration/Tampering but exceeds the false-positive budget.
- The next model work should combine discriminative transfer, world-state novelty and benign support/OOD evidence using development-only pseudo-unseen folds; it should not tune against these now-exposed V47 held-out outcomes and call them fresh evidence.

## Reproduction

GitHub Actions run `35089609851` completed the strict pre-onset audit, three-seed leave-one-family-out benchmark, compact summary and evidence artifact successfully. A later head also passed the same V47 workflow plus the full Krishna integration regression.
