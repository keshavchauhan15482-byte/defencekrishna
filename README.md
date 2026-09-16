# Krishna Defence System — Garuda AI

**SIH26153 · AI-based Network Attack Forecasting from Network Traffic Data**

Krishna Defence is a research prototype for learning evolving network state, forecasting malicious progression, and routing evidence into three defensive lanes: **Arjuna** for reviewed known threats, **Krishna** for novel/unsupported cases and evidence collection, and **Sudarshana** for scoped operator-approved lockdown controls.

## Start here

- **Current evidence:** [`RELEASE_EVIDENCE.md`](RELEASE_EVIDENCE.md)
- **Authoritative unseen-family result:** [`docs/release/V48_RESULTS.md`](docs/release/V48_RESULTS.md)
- **CICAPT temporal/timeline evidence:** [`docs/release/V52_CICAPT_TIMELINE.md`](docs/release/V52_CICAPT_TIMELINE.md)
- **SIH submission material:** [`sih_submission/`](sih_submission/)
- **Historical/failed experiments:** [`docs/archive/`](docs/archive/)

## Current headline evidence

The strongest current controlled result is the frozen V48 X-IIoTID reserve-family benchmark. `exploitation` and `c&c` were excluded from V48 fitting/calibration/fusion selection. Across seeds 42/43/44:

| Reserve family | Recall | FPR | F1 | Release gate |
|---|---:|---:|---:|---|
| Exploitation | **91.88% ± 0.60 pp** | **0.390% ± 0.042 pp** | 94.41% | **PASS 3/3** |
| Command & Control | **87.63% ± 2.69 pp** | **0.366%** | 92.08% | **PASS 3/3** |

This supports **controlled public-dataset unseen-family generalisation**. It does not prove detection of a truly undisclosed real-world zero-day, verified compromise prevention, or production enterprise readiness.

V52 provides strict timestamp/provenance and warning-before-event evaluation machinery. A commit-pinned third-party CICAPT `attack_info.csv` copy passes the development audit and an independent Sandcat-row cross-check, but `publisher_verified = false`; successful-compromise lead time is therefore not claimed.

## Run the offline Garuda demo

Use Python 3.12. On a connected machine, install dependencies once:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r garuda_v3/requirements.txt
python -m garuda_v3.integrated_server
```

Open `http://127.0.0.1:8090`. The demo uses local artifacts and does not require cloud inference. See [`garuda_v3/V3_README.md`](garuda_v3/V3_README.md) for architecture, model/runtime boundaries and detailed commands.

## Repository map

- `garuda_v3/` — forecasting, evaluation, V48/V52 pipelines, artifacts and tests.
- `datasets/` — dataset manifests, provenance and prepared/recovered evidence.
- `sih_submission/` — SIH-facing architecture/demo/submission material; verify dates and metrics against `RELEASE_EVIDENCE.md` before presenting.
- `security_validation/` — defensive validation material.
- `docs/release/` — current release evidence only.
- `docs/archive/` — superseded, exploratory and failed research retained for auditability.
- `proxy.js` + root JS modules — legacy WAF/control runtime retained for compatibility; they are not the source of the V48 benchmark claim.

## Tests

Primary Garuda tests:

```bash
OPENBLAS_NUM_THREADS=1 python -m unittest discover -s garuda_v3/tests -v
python ntro-world-model/tests/test_data_integrity.py
python tests/test_proxy_exposure.py
```

Additional legacy/control checks remain available through `package.json`. Test counts change as coverage grows, so this README intentionally does not freeze a stale global count.

## Evidence discipline

Krishna Defence keeps failed experiments instead of deleting them. Earlier host/service-graph runs, V46/V47 failures and superseded console/benchmark reports are archived because they are useful research history, but they are **not current release evidence**. GNN superiority over LSTM is not claimed where it was not demonstrated.

The project uses an autoregressive state-dynamics **world-model approximation**; it does not claim a fully causal world model. Forecast horizon is not automatically warning lead time, and a timestamped attack step is not automatically a successful-compromise timestamp.

For the exact current claim boundary and evidence matrix, use [`RELEASE_EVIDENCE.md`](RELEASE_EVIDENCE.md).
