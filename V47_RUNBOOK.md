# V47 execution runbook

1. Download the public X-IIoTID CSV and verify that class1/class2/class3 are present.
2. Run strict network-only feature audit; process/system/alert/login fields are rejected.
3. Build contiguous 8-minute histories and 4-minute future targets.
4. Freeze temporal train/calibration/policy/test blocks with a 12-minute embargo.
5. For each selected held-out family, remove every sequence containing that family in history or target from model-development blocks.
6. Train the LSTM state-transition model from seeds 42/43/44 and compare validation state MSE against persistence.
7. Fit the benign future-trajectory reference from calibration benign data only.
8. Choose the alert threshold from policy benign scores only under the 1% empirical FPR budget.
9. Evaluate held-out-family positives and clean benign negatives without retuning.
10. Report all seeds, per-family support, 1/2/3/4-minute recall, benign FPR, precision/F1, state MSE versus persistence, and known-attack logistic baseline.

A family passes only if all reported seeds have FPR <=1% and recall >=80%, with at least 20 held-out-family positives and 50 benign negatives. Passing is evidence of controlled unseen-family generalisation, not a real-world zero-day claim.
