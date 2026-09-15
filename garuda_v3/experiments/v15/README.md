# Garuda V15 — X-IIoTID research branch

This directory preserves the exact validated V15 experiment sources inside the full Krishna Defence System repository.

## Pinned sources

- `v15_xiiotid_pilot_v2.py` — LSTM + logistic temporal pilot, imported from validated commit `2e66dbbb28db8038017a915a82198e1690015cec`.
- `v15_xiiotid_gnn_lstm.py` — topology-aware GraphSAGE-style + LSTM experiment, imported from validated commit `271e5bb2625e138e9025a63c2131257127fc29a6`.
- `SOURCE_SHA256.txt` records the imported source hashes.

Dataset provenance and frozen measured results are stored under `datasets/v15/`.

## What V15 proves

The experiment uses 8 minutes of observed history to predict whether attack-labelled malicious activity appears in the next 4 minutes on a chronological X-IIoTID split with a 12-minute embargo. The untouched test contains 2,521 sequences: 1,366 benign and 1,155 attack targets.

The three-seed LSTM mean observed FPR is 0.0000 on this finite test population, with 86.09% mean recall. This means **zero false positives were observed among 1,366 benign test sequences per seed**; it is not a claim that the population false-positive rate is truly zero. The GNN+LSTM branch has approximately 0.756% mean observed FPR and 80.00% mean recall, and does not outperform the LSTM.

## Critical limits

- The untouched test has zero clean-history future-positive examples in all three seeds. Verified pre-attack/pre-compromise warning lead time is therefore **not established**.
- The pilot's numeric feature selector can include system/process telemetry from X-IIoTID. A strict network-only feature audit/ablation is still required before using this as pure network-traffic-only SIH evidence.
- V15 uses 60-second host-minute telemetry. The current live Garuda v3 service uses a 10-second graph/checkpoint schema. These are not drop-in compatible.
- Therefore the V15 result is integrated into Krishna Defence as the latest measured Garuda evidence and a fail-closed response-policy gate. It does not replace the live runtime checkpoint yet.

## Reproduction environment

Use the separate requirements in this directory and install CPU PyTorch as noted there. Do not add PyTorch/pandas/scikit-learn to the lightweight production-facing serving environment only to run this research experiment.
