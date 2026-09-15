## V12 measured risk-readout experiment

See [V12_RESULTS.md](V12_RESULTS.md). 27 diagnostic fits tested whether frozen state forecasts help future malicious-flow prediction. Attack-risk gates failed; no model was promoted. Calibration/policy data readiness is now checked explicitly.

## V11 protection and evidence audit

See [V11_RESULTS.md](V11_RESULTS.md) for escalation/unlock/policy fixes, actual HTTP enforcement receipts, and the remaining verified-timeline gate. This is not a 9/10 or production certification.

## V10 targeted forecasting upgrade

See [V10_RESULTS.md](V10_RESULTS.md): dataset-separated and controlled three-seed runs, state-loss/selection fixes, 14.23% LSTM and 10.43% GNN state-MSE reductions versus persistence on a reused CICAPT holdout. These are not attack-detection scores. Existing defence defaults and data are preserved.

## V9 additive dataset expansion

See [V9_DATASET_RESULTS.md](V9_DATASET_RESULTS.md) for the added CICAPT/CTU data, reproducible comparison and limitations. Existing IDS2018 data and default models are preserved. The new candidate did not beat persistence and is not promoted.

> Latest experiment and autoplay update: [V8_RESULTS.md](V8_RESULTS.md). Experimental results do not pass the enterprise release gates.

> Latest core-pipeline work: read [CORE_UPGRADE_RESULTS.md](CORE_UPGRADE_RESULTS.md) for calibrated/masked training, the fresh DoS holdout, shadow collector and failed release gates. New experimental models are not production-approved.

> **Console 5:** stage hints, matched three-seed comparisons, a 51-host replay and hosted HTTP protection rehearsal. See [CONSOLE_V5.md](CONSOLE_V5.md).

> **New: Command Console 4** — interactive 3D telemetry, forecast timeline, defence signal routing and reviewed snapshot memory. See [CONSOLE_V4.md](CONSOLE_V4.md) for setup, lab automation and test scope.

# Krishna Defence - Garuda v3

SIH26153 / Team The Predators

**New real-PCAP experiment:** Four original IDS2018 capture members, one log, 1,549 host/packet graph windows and a trained research checkpoint are now included. The cross-family benchmark failed (40/40 negative examples falsely alerted), so it is **not** the default model. Read [IDS2018 results](garuda_v3/IDS2018_RESULTS.md) and [data provenance](datasets/ids2018/README.md). This is not zero-day or market-readiness proof.

**September 11 residual-decoder update:** Read [the three-fix status](garuda_v3/FIX_STATUS.md) before presenting results. The default demo uses the retrained seed-42 residual GNN. Verified early-warning and real host/packet-stage evidence still require additional telemetry.

**Current entrypoint: the authenticated Garuda v3 offline demo.** This revision includes trained directed GraphSAGE + LSTM models, actual graph datasets, future-only evaluation, explanations and expiring operator-approved proxy rules. It is an internally evaluated research prototype, not a certified enterprise product.

## Start

Use Python 3.12. Install dependencies once on a connected machine:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r garuda_v3/requirements.txt
python -m garuda_v3.server
```

Open **http://127.0.0.1:8090**. Copy a viewer token from `garuda_v3/runtime/access.json` into the access field, connect, then choose **Explore recorded traffic** or **Run alert replay**. The token file is created locally with restricted permissions; it is never packaged. Inference uses NumPy and local model artifacts, without cloud APIs. Training additionally uses scikit-learn.

On Windows, activate with `.venv\Scripts\activate` before the Python commands. `run_demo.sh` now launches this v3 demo on Unix-like systems.

## What is included

- `garuda_v3/artifacts/Thursday.npz` and `Friday.npz`: 6,453 observed protocol/service graph windows from the supplied CSVs.
- `garuda_v3/artifacts/residual_run`: current primary checkpoints, test predictions, hashes and metrics. `artifacts/run` retains the previous model.
- `garuda_v3/artifacts/residual_seed7`, `residual_seed19`, `residual_comparison.json`: current initialization comparison; older seed runs are retained.
- `garuda_v3/V3_README.md`: architecture, commands, model card, deployment boundary and limitations.
- `sih_submission`: previous-revision PPTX/PDF and recording script. Read `READ_BEFORE_PRESENTING.md`; their numerical results predate this update.
- `garuda_v3/tests`: model/data/security/PCAP and live local proxy enforcement tests.

## Measured result, with scope

Primary seed 42, 160 chronological test examples, target = malicious flow presence in the fourth future 10-second window:

| Model | F1 | Precision | Recall | FPR |
|---|---:|---:|---:|---:|
| Logistic regression | 91.6% | 98.1% | 86.0% | 5.1% |
| Residual LSTM | 95.8% | 98.3% | 93.4% | 5.1% |
| Residual GNN + LSTM | 94.9% | 98.2% | 91.7% | 5.1% |

Three-seed residual GNN mean F1 is 96.0%. These are reused internal holdout results, not a new blind evaluation or demonstrated compromise warning. The clean-history test has only one future positive and it is still missed. Primary GNN state MSE is now 0.0127064 versus 0.0127354 persistence; the small improvement has a paired interval crossing zero. The residual LSTM remains stronger on this dataset. No model is approved for production automatic containment. Console v4 adds explicitly armed, operator-bound lab automation only; see CONSOLE_V4.md.

The supplied Friday file is labelled Bot/Benign, despite its Infiltration filename. Source/destination IPs are absent, so the trained graphs describe protocol/service relationships. Host graphs and packet parsing are implemented, but real host/packet-trained checkpoints and supervised MITRE stages require additional annotated telemetry.

## Tests

```bash
OPENBLAS_NUM_THREADS=1 python -m unittest discover -s garuda_v3/tests -v
python ntro-world-model/tests/test_data_integrity.py
python tests/test_proxy_exposure.py
```

Node.js is needed for the proxy integration test (tested with Node 24.19.0). See `garuda_v3/VERIFICATION.md`.

## Legacy modules

The original WAF/detection engines remain available via `node proxy.js`; the listener defaults to loopback. Legacy management routes now require `GARUDA_OPERATOR_TOKEN` with at least 32 characters. Forwarded client IPs are trusted only for explicitly configured `TRUSTED_PROXY_IPS`. The old prediction-to-lockdown route is retired.

`ntro-world-model`, `LEGACY_README.md`, old HTML reports and old benchmark scripts are historical reference. Their prior production, zero-day, accuracy or lead-time claims are superseded by the v3 model card and measured artifacts. Do not use legacy metrics in the SIH presentation.
