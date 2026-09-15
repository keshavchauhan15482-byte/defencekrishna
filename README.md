## V15 integrated Krishna Defence System

See [V15_SYSTEM_INTEGRATION_RESULTS.md](V15_SYSTEM_INTEGRATION_RESULTS.md) for the measured system integration. Garuda V15 is now part of the real Krishna Defence forecast/response path as the latest X-IIoTID evidence and a fail-closed response-policy gate. Start the integrated local demo with `npm run demo:v15`.

Important boundary: the live compatible runtime remains the hash-checked Garuda v3 10-second graph forecaster. V15 was evaluated on 60-second X-IIoTID host-minute telemetry and still needs a strict network-only audit plus a schema-compatible checkpoint export before it can honestly replace that runtime model. Current V15 unknown-forecast containment therefore remains shadow-only. Arjuna reviewed/known enforcement and operator-scoped Sudarshana lab controls retain their separately tested behavior.

Fresh V15 X-IIoTID evidence: LSTM three-seed mean recall **86.09%** with **0 false positives observed among 1,366 benign test sequences per seed** on this finite chronological holdout; GraphSAGE-style+LSTM mean observed FPR **0.7565%** and recall **80.00%**. The untouched test has zero clean-history future-positive examples, so verified pre-compromise warning is not claimed.

## Historical V12 measured risk-readout experiment

See [V12_RESULTS.md](V12_RESULTS.md). 27 diagnostic fits tested whether frozen state forecasts help future malicious-flow prediction. Attack-risk gates failed; no model was promoted. Calibration/policy data readiness is now checked explicitly.

## V11 protection and evidence audit

See [V11_RESULTS.md](V11_RESULTS.md) for escalation/unlock/policy fixes, actual HTTP enforcement receipts, and the remaining verified-timeline gate. This is not a 9/10 or production certification.

## V10 targeted forecasting upgrade

See [V10_RESULTS.md](V10_RESULTS.md): dataset-separated and controlled three-seed runs, state-loss/selection fixes, 14.23% LSTM and 10.43% GNN state-MSE reductions versus persistence on a reused CICAPT holdout. These are not attack-detection scores. Existing defence defaults and data are preserved.

## V9 additive dataset expansion

See [V9_DATASET_RESULTS.md](V9_DATASET_RESULTS.md) for the added CICAPT/CTU data, reproducible comparison and limitations. Existing IDS2018 data and default models are preserved. The new candidate did not beat persistence and is not promoted.

> Historical V8 experiment and autoplay update: [V8_RESULTS.md](V8_RESULTS.md). Experimental results do not pass the enterprise release gates.

> Historical core-pipeline work: read [CORE_UPGRADE_RESULTS.md](CORE_UPGRADE_RESULTS.md) for calibrated/masked training, the fresh DoS holdout, shadow collector and failed release gates. New experimental models are not production-approved.

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
python -m garuda_v3.integrated_server
```

Open **http://127.0.0.1:8090**. Copy a viewer token from `garuda_v3/runtime/access.json` into the access field, connect, then choose **Explore recorded traffic** or **Run alert replay**. The token file is created locally with restricted permissions; it is never packaged. Inference uses NumPy and local model artifacts, without cloud APIs. Training additionally uses scikit-learn.

On Windows, activate with `.venv\Scripts\activate` before the Python commands. `npm run demo:v15` launches the integrated local demo.

## What is included

- `garuda_v3/artifacts/Thursday.npz` and `Friday.npz`: 6,453 observed protocol/service graph windows from the supplied CSVs.
- `garuda_v3/artifacts/residual_run`: current primary runtime checkpoints, test predictions, hashes and metrics. `artifacts/run` retains the previous model.
- `garuda_v3/experiments/v15`: pinned validated V15 LSTM/logistic and GraphSAGE-style+LSTM experiment sources and source hashes.
- `datasets/v15`: persisted fresh X-IIoTID V15 evidence and provenance.
- `garuda_v3/v15_bridge.py` and `garuda_v3/integrated_server.py`: measured V15 evidence/policy integration into the real Krishna Defence path.
- `garuda_v3/V3_README.md`: architecture, commands, model card, deployment boundary and limitations.
- `sih_submission`: previous-revision PPTX/PDF and recording script. Read `READ_BEFORE_PRESENTING.md`; their numerical results predate this update.
- `garuda_v3/tests`: model/data/security/PCAP, V13/V14 integrity, V15 system integration and live local proxy enforcement tests.

## Measured result, with scope

The current live compatible runtime checkpoint still uses the existing 10-second Garuda v3 graph schema. Its historical primary seed-42 internal result remains:

| Model | F1 | Precision | Recall | FPR |
|---|---:|---:|---:|---:|
| Logistic regression | 91.6% | 98.1% | 86.0% | 5.1% |
| Residual LSTM | 95.8% | 98.3% | 93.4% | 5.1% |
| Residual GNN + LSTM | 94.9% | 98.2% | 91.7% | 5.1% |

The newer V15 X-IIoTID experiment is the stronger fresh temporal-risk evidence, but it is not yet a schema-compatible runtime checkpoint. Its LSTM three-seed mean observed FPR is 0 on the finite test population with 86.09% recall; the topology-aware GNN+LSTM mean observed FPR is 0.7565% with 80.00% recall. See the V15 integration report for exact scope and limitations.

These are future-malicious-traffic results, not verified compromise prediction. No model is approved for production automatic containment. Current V15 unknown forecasts are shadow-only; reviewed Arjuna memory and explicit operator-scoped Sudarshana lab enforcement remain separately tested.

The supplied Friday file is labelled Bot/Benign, despite its Infiltration filename. Source/destination IPs are absent, so the older trained graphs describe protocol/service relationships. Host graphs and packet parsing are implemented, but a strict network-only, schema-compatible V15 checkpoint and supervised MITRE stages require additional annotated telemetry.

## Tests

```bash
OPENBLAS_NUM_THREADS=1 python -m unittest discover -s garuda_v3/tests -v
python ntro-world-model/tests/test_data_integrity.py
python tests/test_proxy_exposure.py
npm run test:v11
```

The final integrated branch passed 91 Garuda Python tests, 7 NTRO integrity tests, 5 proxy exposure checks, 15 strict V11 controls, 12 real loopback HTTP checks, 2 V11 evidence tests, and a separately executed 10-test V15 system-integration contract. See `V15_SYSTEM_INTEGRATION_RESULTS.md` for run IDs and evidence scope.

## Legacy modules

The original WAF/detection engines remain available via `node proxy.js`; the listener defaults to loopback. Legacy management routes now require `GARUDA_OPERATOR_TOKEN` with at least 32 characters. Forwarded client IPs are trusted only for explicitly configured `TRUSTED_PROXY_IPS`. The old prediction-to-lockdown route is retired.

`ntro-world-model`, `LEGACY_README.md`, old HTML reports and old benchmark scripts are historical reference. Their prior production, zero-day, accuracy or lead-time claims are superseded by the v3/V15 model cards and measured artifacts. Do not use legacy metrics in the SIH presentation.
