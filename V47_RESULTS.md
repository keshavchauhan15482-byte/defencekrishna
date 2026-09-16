# V47 unseen-family benchmark results

This report records the executed X-IIoTID family-disjoint experiment. It is a controlled **unseen-family / zero-supervised-exposure** benchmark, not proof of a real undisclosed zero-day or verified pre-compromise lead time.

## Executed protocol

- Public X-IIoTID source downloaded independently in GitHub Actions.
- Source: 820,834 rows / 68 columns / SHA-256 `7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0`.
- Strict network-only numeric feature allow-list: 21 raw traffic fields; process/resource/OSSEC/login/class fields excluded.
- 8-minute observed history, 4-minute future trajectory.
- Seeds 42, 43, 44; no best-seed promotion.
- Held-out family removed from training, state validation, calibration and policy fitting.
- Benign-only policy threshold targets <=1% empirical FPR on the development policy block.
- Five families selected by support count only: Tampering, Lateral Movement, Weaponization, Exfiltration, Reconnaissance.
- Test benign support: 1,366 sequences for every selected family.

The strict chronological pre-onset audit found **zero eligible held-out-family future positives in the final chronological test tail for every family**. Therefore X-IIoTID cannot establish the SIH pre-compromise/clean-history warning claim under this split. The leave-one-family-out benchmark below measures family-disjoint generalisation, not advance warning.

## World-state forecasting and open-set warning

| Held-out family | Positive support | Validation state gate | Mean world recall ± SD | Mean benign FPR ± SD | Unseen-family gate |
|---|---:|---|---:|---:|---|
| Tampering | 1,876 | pass all seeds | 0.00% ± 0.00 | 3.34% ± 1.90 | fail |
| Lateral Movement | 1,598 | pass all seeds | 32.67% ± 0.49 | **0.317% ± 0.042** | fail recall |
| Weaponization | 557 | pass all seeds | 12.15% ± 6.21 | **0.317% ± 0.042** | fail recall |
| Exfiltration | 471 | pass all seeds | 0.00% ± 0.00 | **0.390% ± 0.085** | fail recall |
| Reconnaissance | 364 | **fails persistence** | 16.85% ± 5.87 | **0.415% ± 0.112** | fail state + recall |

The open-set future-trajectory score is conservative on four families but misses too many unseen attacks. **No held-out family passes FPR <=1% and recall >=80% across all seeds.**

For Lateral Movement, Weaponization and Exfiltration, the learned world-model state forecast itself beats persistence on the held-out evaluation set, so the central failure is not always state prediction; it is the conversion of that trajectory into a useful open-set warning score.

## Known-attack logistic baseline on the same unseen families

The logistic history baseline was trained without the held-out family and evaluated on exactly the same positives/benign negatives.

| Held-out family | Recall | Benign FPR |
|---|---:|---:|
| Tampering | 87.42% | 3.37% |
| Lateral Movement | 57.45% | 1.39% |
| Weaponization | **98.38%** | 2.78% |
| Exfiltration | **99.79%** | 2.05% |
| Reconnaissance | 40.66% | 1.61% |

This is useful evidence that features learned from other attacks can transfer to unseen families, but the baseline violates the <=1% false-positive release budget on every selected family.

## Clean-history / pre-onset support

Leave-one-family-out clean-history onset positives were:

- Tampering: 0
- Lateral Movement: 0
- Weaponization: 6
- Exfiltration: 0
- Reconnaissance: 0

The strict chronological pre-onset protocol selected no family at all because the final chronological tail contains no supported held-out-family future onset. Therefore **verified advance warning / compromise lead time remains unproven** on X-IIoTID.

## Main finding

V47 narrows the problem substantially:

1. family-disjoint state dynamics can generalise for several held-out families;
2. the current benign predicted-trajectory manifold score is too conservative and has poor unseen recall;
3. the discriminative baseline transfers strongly to some held-out families, but exceeds the false-positive budget;
4. the next score should be selected using development pseudo-unseen families and combine temporal/world-model evidence with transferable attack evidence, then be frozen before evaluating any still-unseen reserve family;
5. these five V47 families are now exposed diagnostics and must never be relabelled as a fresh final holdout after score tuning.

## Reproduction

- V47 workflow latest green head: GitHub Actions run `35089717060`.
- Full Krishna integration regression on the same head: run `35089717012`, all steps successful.
- Evidence artifact includes strict pre-onset support report, per-family three-seed reports and leave-one-family-out summary.
