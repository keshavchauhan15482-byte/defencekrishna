# V58 independent RDoS holdout audit — 20 September 2026

## Purpose

This audit checks whether the already-frozen V55 alert fusion transfers to a network-attack family that was not part of V55 development or reserve evaluation. The scorer configuration is reused without modification. RDoS is blocked from fit, calibration, and policy data before evaluation.

Authoritative GitHub Actions run: `35520642524`  
Evaluated head: `f1363a81d2db2a7fe5885ae1082da2c35dd59e18`  
Seeds: `42, 43, 44`  
Dataset: X-IIoTID  
Source SHA-256: `7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0`  
Frozen V55 config SHA-256: `868781f12dc6fa1b90640e309303c1cca7d4e8140dbb6952ea372a96b0c14e51`  
Workflow artifact SHA-256: `b386fcc00d8b124af523b8239dcf750a334621f6bfb9493a715beff6d7285f01`

## Audit contract

- `selection_reused_without_modification = true`
- `holdout_metrics_used_for_selection = false`
- `holdout_blocked_from_fit_calibration_policy = true`
- Prior V55 families: C&C, exfiltration, exploitation, lateral movement, reconnaissance, tampering, weaponization
- Fresh holdout family: RDoS

## Support

- Train sequences: 21,219
- Calibration sequences: 3,737
- Policy sequences: 2,700
- Clean test negatives: 1,366
- RDoS positive future windows: 12

## Result

| Seed | TP | FN | FP | TN | Recall | FPR | Precision | F1 | State forecast vs persistence |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 42 | 12 | 0 | 8 | 1358 | 100.0% | 0.586% | 60.0% | 75.0% | PASS |
| 43 | 12 | 0 | 8 | 1358 | 100.0% | 0.586% | 60.0% | 75.0% | FAIL |
| 44 | 12 | 0 | 7 | 1359 | 100.0% | 0.512% | 63.16% | 77.42% | FAIL |

Three-seed mean:

- Recall: **100.0% ± 0.0 pp**
- FPR: **0.561% ± 0.042 pp**
- Precision: **61.05% ± 1.82 pp**
- F1: **75.81% ± 1.40 pp**
- Alert reference gate (recall >= 80%, FPR <= 1%): **PASS 3/3 seeds**
- Validation state gate: **PASS 3/3 seeds**
- Held-out RDoS test-state forecasting beats persistence: **PASS 1/3 seeds**

## Interpretation

The frozen V55 alert fusion detected all 12 RDoS positive windows in every seed while keeping false-positive rate below 1%. This is evidence that the alert scorer transfers to one fresh X-IIoTID attack family under the stated protocol.

The forecasting-state result is weaker: the state model beat persistence on the RDoS test slice in only seed 42. Therefore this audit supports the alert-detection gate, but it does **not** support a claim that future-state forecasting generalises better than persistence on RDoS across all seeds.

The positive support is only 12 RDoS windows, so this result should be treated as a small-sample independent-family audit rather than broad real-world zero-day proof.

## Claim boundary

This is an independent family holdout **inside X-IIoTID**. It is not a cross-dataset test, not a live Internet attack, not an undisclosed zero-day, and not production containment evidence. A separate cross-dataset/campaign evaluation is still required for a stronger external-validity claim.
