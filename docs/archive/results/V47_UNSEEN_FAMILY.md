# V47 — Unseen-family open-set forecasting protocol

V47 is the next evidence track for SIH26153. Its purpose is to test whether Garuda can forecast malicious future states when an entire attack family is absent from training and policy selection.

## Why this matters

The SIH problem asks for a World Model that learns evolving network state, forecasts future malicious activity and attacker progression, and supports proactive defence before compromise is completed. A classifier that only recognizes attack families seen during training is not sufficient evidence for that goal.

V47 therefore evaluates **family-disjoint generalisation**. It is an honest simulation of unseen/novel attacks. It must not be advertised as proof of a real-world zero-day because the held-out families are known to the dataset publisher and are used after inference for evaluation.

## Dataset

The first V47 benchmark uses the public X-IIoTID dataset because it contains hierarchical attack labels and multiple attack families, including reconnaissance, weaponisation, exploitation, lateral movement, command-and-control, exfiltration, tampering, ransomware and RDoS.

The workflow downloads the public source independently; the raw dataset is not committed to this repository.

## Strict network-only feature audit

V47 does **not** reuse the earlier V15 automatic numeric feature selector. Only an explicit allow-list of network/flow/packet numeric fields is eligible, for example duration, byte/packet counts, byte/packet rates and ratios, retransmission/missing-byte indicators, TCP-flag-derived fields, RTT and ports.

The following X-IIoTID evidence sources are excluded from model input:

- CPU/memory/device-resource telemetry;
- process/file activity;
- OSSEC/IDS alert fields;
- login fields;
- attack/class labels;
- source/destination IP identifiers as learned numeric features.

IP addresses may be used only to group contiguous source-host timelines; they are not model features.

## Unseen-family split

For each held-out family F:

1. Any sequence containing F in observed history **or future target** is removed from train, state-validation, benign-reference fitting and policy-threshold fitting.
2. Train/validation/policy remain chronological with a 12-minute embargo.
3. Test positives are later sequences where F was absent from the complete 8-minute observed history and appears in the next 1–4 minutes.
4. Test negatives are later sequences with a clean benign history and benign future.
5. Family labels are used only to construct this split and score the frozen predictions. They are never provided to the model.

This means the model has zero supervised exposure to the held-out attack family before evaluation.

## Models and scores

### Temporal world model

A small LSTM learns the next four network states from the prior eight minute states. State training uses future-state MSE only.

The state checkpoint must beat persistence on family-free validation data. This remains separate from attack scoring.

### Open-set future-trajectory score

The world model predicts the next four states. A robust benign reference distribution is fit using **calibration benign predictions only**. The alert score is the robust distance of the predicted future trajectory from this benign forecast manifold.

The alert threshold is then chosen using **policy benign scores only** under the 1% empirical FPR budget. No held-out-family positive is used to fit the anomaly reference or threshold.

### Known-attack logistic baseline

A logistic history classifier is trained on benign versus the remaining known attack families. It is evaluated on exactly the same unseen-family positives and benign negatives. This tests whether a conventional discriminative model transfers as well as the open-set world-forecast score.

## Reported evidence

For each selected held-out family and seeds 42/43/44, V47 reports:

- validation state MSE vs persistence;
- test state MSE vs persistence;
- unseen-family recall and benign FPR;
- precision/F1;
- clean-history unseen-family recall where support exists;
- 1/2/3/4-minute horizon metrics;
- known-family logistic baseline;
- seed mean/SD;
- support counts and skipped-family reasons.

Families are selected only by minimum support / positive-count size, never by model performance. The workflow currently evaluates up to five largest supported families to keep CI bounded; all support counts remain visible.

## Claim boundary

Passing this benchmark would support the claim:

> Garuda generalises to attack families excluded from model development under a controlled public-dataset simulation.

It would **not** prove:

- detection of an undisclosed real zero-day in production;
- verified pre-compromise lead time;
- successful prevention of compromise;
- supervised MITRE progression accuracy unless those labels are separately verified;
- enterprise deployment readiness.

Those stronger claims still require independently reserved campaigns, verified incident outcomes/timestamps, clean pre-attack histories and a final untouched evaluation.
