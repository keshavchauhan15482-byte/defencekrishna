# Krishna Defence System — Garuda V15 integration results

Date: 2026-09-15

## Scope

This release integrates the fresh Garuda V15 X-IIoTID evidence into the **actual Krishna Defence System codebase**, rather than treating V15 as a standalone project. The repository supplied for integration was a complete extracted system snapshot whose top-level README still identified V12 as the latest risk-readout work. Key documented V13/V14 safety/data-integrity gates were therefore restored before V15 was connected.

V15 is the Garuda AI research/evidence branch. Krishna Defence remains the full system: Garuda forecasting → Arjuna reviewed/known path → Krishna unknown-risk triage → Sudarshana scoped containment.

## Before/after regression baseline

Before changing the system, GitHub Actions run `34989115072` established a clean baseline:

- 69 Garuda Python tests passed.
- 7 NTRO data-integrity checks passed.
- 5 proxy-exposure checks passed.
- 15 V11 strict Node control checks passed.
- 12 actual loopback HTTP enforcement checks passed.
- 2 V11 evidence unit tests passed in the V11 script.

After integration, run `34989697972` passed the complete regression with:

- 89 Garuda Python tests passed, including 5 restored V13 policy tests, 7 restored V14 verified-campaign/data-gate tests, and 8 V15 system-integration tests.
- 7 NTRO data-integrity checks passed.
- 5 proxy-exposure checks passed.
- 15 V11 strict Node control checks passed.
- 12 actual loopback HTTP enforcement checks passed.
- 2 V11 evidence tests passed in the V11 script.
- The 8 V15 integration tests also passed as a separately named CI step.

A later post-V14-CLI integration run `34989809635` also completed successfully.

## Fresh V15 forecasting evidence now stored in the system

X-IIoTID source provenance:

- 820,834 rows, 68 columns.
- CSV size: 355,308,902 bytes.
- SHA-256: `7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0`.
- History: 8 minutes.
- Forecast target: any attack-labelled malicious activity in the next 4 minutes.
- Chronological split with 720-second embargo.
- Untouched test: 2,521 sequences = 1,366 benign + 1,155 attack targets.

### Same-test model results

| Model | Observed FPR | Recall | Precision | F1 | PR-AUC | Brier |
|---|---:|---:|---:|---:|---:|---:|
| Logistic history | 0.2196% | 86.58% | 99.70% | 92.68% | 0.9948 | 0.0302 |
| LSTM, 3-seed mean | 0.0000% observed | 86.09% | 100.00% | 92.51% | 0.9915 | 0.0461 |
| GraphSAGE-style + LSTM, 3-seed mean | 0.7565% | 80.00% | 98.90% | 88.44% | 0.9838 | 0.2738 |

For the LSTM, “0.0000% observed FPR” means **zero false positives were observed among 1,366 benign test sequences per seed on this finite chronological holdout**. It does not establish a true population FPR of zero.

The GNN branch is implemented and tested on 84,120 unique minute-level source→destination edges, but it does not outperform the LSTM. It remains useful for topology/state/explanation research rather than being presented as the best risk scorer.

## What is now integrated into the real system

1. **Pinned V15 experiment source and evidence** live inside the full repository under `garuda_v3/experiments/v15/` and `datasets/v15/`.
2. **V15 evidence bridge** validates provenance and exposes the latest LSTM/GNN metrics to the real Garuda/defence path.
3. **Fail-closed authority gate** prevents a strong research forecast from silently becoming an autonomous unknown-attack block.
4. **Actual response coordinator** now distinguishes reviewed Arjuna memory from unknown Krishna forecast signals. Current V15 unknown forecasts remain shadow-only even when the lab target is armed.
5. **Sudarshana/operator path** retains the existing scoped signed enforcement mechanics and explicit breach escalation.
6. **Integrated server entrypoint** (`npm run demo:v15`) runs the existing hash-checked Garuda graph forecaster while attaching V15 evidence and policy status to each forecast.
7. **Dashboard** surfaces V15 LSTM recall/FPR, untouched-test support, clean-onset count, network-only audit status, runtime-schema compatibility, and whether autonomous unknown containment is approved.
8. **V13/V14 evidence hygiene** is restored: fail-closed threshold export, verified campaign manifests, explicit benign intervals, immutable campaign split support, training-only grouped hard-negative support, and readiness checks.

## Why the live runtime model is not silently replaced by V15

The current Garuda serving checkpoint consumes 10-second graph windows. V15 was trained/evaluated on 60-second X-IIoTID host-minute telemetry and its selected numeric inputs can include system/process fields. Replacing the live checkpoint with the V15 model without a network-only, schema-compatible training/export pass would be technically invalid.

Therefore the honest integrated architecture is:

**live compatible Garuda v3 graph forecaster → V15 latest evidence/policy guard → Krishna Defence response orchestration.**

The next model-runtime upgrade should retrain/export the stronger temporal approach on a strict network-only representation compatible with the live graph ingestion contract, then repeat calibration/policy/final evaluation on newly reserved data.

## Remaining evidence gates

- Untouched V15 test has **zero clean-history future-positive examples** in all three LSTM seeds; verified pre-attack/pre-compromise warning remains unproven.
- Strict network-only X-IIoTID ablation/audit is pending.
- A V15 checkpoint compatible with the 10-second live Garuda graph schema is pending.
- Supervised future MITRE-stage validation is pending.
- Independent customer/on-prem integration, sustained load/security testing and production enforcement approval are pending.

These limits are deliberately visible in code, CI evidence and the dashboard; they are not hidden by a demo score.
