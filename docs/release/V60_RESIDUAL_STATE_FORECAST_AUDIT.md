# V60 residual state forecasting diagnostic — 20 September 2026

## Purpose

V58 showed strong unseen-family alert detection on RDoS, but the legacy absolute-state forecaster did not consistently beat persistence on the held-out RDoS state slice. V60 changes the state model to a persistence-anchored residual forecaster and chooses its residual/trend blend using leakage-safe calibration data only.

RDoS had already been inspected in V58. Therefore V60 is a post-diagnostic engineering test, not a fresh independent holdout claim.

Authoritative GitHub Actions run: `35522069892`  
Evaluated head: `ea7f894fed19a5d7ddc8b1608732a1388fa55d47`  
Seeds: `42, 43, 44`  
Dataset: X-IIoTID  
Workflow artifact: `v60-residual-state-evidence`  
Workflow artifact SHA-256: `8fe1079bafa4a606df0a3ea3454625d20197ea2275f5e7482857d00cf61722ee`

## Support

- Train sequences: 21,219
- Calibration sequences: 3,737
- Policy sequences: 2,700
- RDoS-positive future windows: 12
- Clean test negatives: 1,366

## Model change

- Persistence is the anchor forecast.
- The LSTM predicts residual future motion rather than the absolute future state.
- A deterministic short recent-trend component is available.
- Residual weight `alpha` and trend weight `beta` are selected from a predeclared grid on calibration MSE only.
- RDoS test outcomes are not used to choose the blend.

## Result

- Legacy model in the V60 comparison run beats persistence on the combined held-out slice: **0/3 seeds**.
- V60 residual model beats persistence on the combined held-out slice: **3/3 seeds**.
- Mean combined held-out test MSE improvement vs persistence: **21.87% lower MSE**.
- Mean RDoS-positive-only MSE improvement vs persistence: **0.052% lower MSE**.

## Interpretation

The persistence-anchored residual architecture fixes the combined held-out state-forecast gate in this diagnostic: all three seeds beat persistence, versus zero of three for the legacy model in the same V60 comparison run.

The positive-only improvement is very small. Therefore V60 supports the claim that the new architecture is more stable than persistence on the combined held-out RDoS evaluation slice, but it does **not** establish a large forecasting advantage specifically on the 12 RDoS-positive windows.

The historical V58 legacy result remains separate: V58 reported the then-current state forecaster beating persistence on 1/3 RDoS seeds. V60 uses a separate 18-epoch comparison run, so its legacy 0/3 result should not be substituted for the earlier V58 record.

## Claim boundary

This is a diagnostic on a previously inspected X-IIoTID holdout family. It is not a fresh zero-day test, not a live Internet attack, and not cross-dataset forecasting proof. Independent-dataset validation remains required before making a stronger external-generalisation claim.
