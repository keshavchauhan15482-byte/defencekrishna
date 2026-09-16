# V45 forecasting evidence hardening

V45 is a **new strict forecasting path**. It does not rewrite historical V8–V15 evidence or claim that the release gates already pass.

## What V45 changes

- **One 10-second graph contract** for CIC-IDS-2018 and CICAPT-IIoT2024. Source hashes, campaign IDs, timestamps, packet-feature presence and network-only provenance are retained.
- **Raw IDS2018 PCAP support.** Packet-derived host/service graphs preserve TTL, TCP-window, fragmentation and retransmission indicators. A packet capture by itself does **not** establish attack truth, so packet-only risk labels remain unknown instead of being fabricated.
- **CTU-13 remains separate.** V45 refuses a training run that mixes CTU-13 with CIC sources.
- **Campaign-level train / validation / final-test split.** The final-test campaign and source hashes are frozen in an immutable reservation file. Test is not used for model selection, class weighting, calibration or threshold selection.
- **Unknown is not benign.** Cumulative targets mean: positive if a known malicious event exists in the next 10/20/30/40 seconds, benign only when the whole horizon is explicitly known benign, otherwise unknown.
- **State-first world model.** Residual LSTM and GNN+LSTM begin at exact persistence. State parameters are trained with future-state MSE only and selected by validation state MSE.
- **Persistence rejection.** If the learned validation state MSE does not beat persistence, risk-head promotion stops. The checkpoint stays research-only.
- **Separate risk head.** After the state checkpoint passes, the world model is frozen and only the risk head is optimized. Aggressive `balance-risk` is not used in V45.
- **Separate MITRE stage head.** It is trained only when explicit `stage_y` supervision exists. Unsupported stages remain unsupported.
- **Validation-only calibration/policy.** Calibration and the 1% FPR policy come from validation traffic only.
- **Abstention.** A training-only feature envelope plus a validation-selected support threshold reports coverage and abstention. This is a descriptive distribution-shift guard, **not** a claim of generic OOD detection.
- **Verified lead time.** First-warning timestamps are derived from saved network-only probabilities and the validation-selected threshold, then aligned post-hoc with independently verified compromise events. Verified timelines are never model inputs.
- **Multi-seed evidence.** Seeds 42/43/44 are reported as mean and sample SD. Seed repeats are not treated as independent campaigns. Campaign-level bootstrap is reported separately.
- **Automatic containment remains disabled.** Passing the forecasting evidence audit does not by itself approve enterprise blocking.

## Prepare new 10-second data

Historical prepared datasets are not overwritten.

Completed-flow input with labels already present in the source:

```bash
python -m garuda_v3.prepare_v45_data ids2018 FLOW.csv \
  --output datasets/v45/ids-day-a.npz \
  --campaign ids-day-a --family DoS --mode host
```

Raw classic IDS2018 PCAP for packet/state evidence. The resulting risk labels remain unknown until independently supported ground truth is attached for evaluation:

```bash
python -m garuda_v3.prepare_v45_data ids2018-pcap datasets/ids2018/raw/Friday-02-03-2018.pcap \
  --output datasets/v45/ids-packet-a.npz \
  --campaign ids-packet-a --family DoS --mode host --max-nodes 64
```

CICAPT-IIoT2024 PCAPNG:

```bash
python -m garuda_v3.prepare_v45_data cicapt CAPTURE.pcapng \
  --output datasets/v45/cicapt-a.npz \
  --campaign cicapt-a --family CICAPT --mode host --max-nodes 64
```

CTU is prepared separately and should be evaluated separately:

```bash
python -m garuda_v3.prepare_v45_data ctu capture.binetflow \
  --output datasets/v45_ctu/ctu-5.npz \
  --campaign ctu-5 --mode service
```

## Freeze the campaign split

Example `datasets/v45/split.json`:

```json
{
  "train": ["ids-day-a", "ids-day-b", "cicapt-dev-a"],
  "validation": ["ids-day-c", "cicapt-dev-b"],
  "test": ["untouched-final-campaign"]
}
```

Every supplied campaign must appear exactly once. `test` is the untouched final evaluation for the experiment.

## Single-seed strict run

```bash
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.train_v45 \
  --graphs datasets/v45/*.npz \
  --split-manifest datasets/v45/split.json \
  --reservation datasets/v45/final_holdout_reservation.json \
  --output garuda_v3/artifacts/v45/seed_42 \
  --seed 42
```

If verified campaign manifests are available, add:

```bash
  --verified-manifests datasets/verified_campaigns/manifests/*.json
```

The tool derives model-specific network warning timestamps before computing verified lead time.

## Three-seed run

```bash
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.v45_multiseed \
  --graphs datasets/v45/*.npz \
  --split-manifest datasets/v45/split.json \
  --reservation datasets/v45/final_holdout_reservation.json \
  --output garuda_v3/artifacts/v45_multiseed \
  --seeds 42 43 44
```

No best seed is promoted.

## Release evidence gate

The post-training `v45_release_gate.json` requires, per model:

1. evaluation scope is a new predeclared holdout;
2. validation state MSE beats persistence;
3. validation calibration is fitted;
4. the validation-selected alert policy exists;
5. each held-out family has minimum positive/negative support and satisfies **FPR ≤ 1%** and **recall ≥ 80%**;
6. clean-history test support contains both benign and future-positive examples;
7. enough independently verified compromise incidents exist and measured lead time is positive.

Failure returns `research_only_insufficient_evidence`. It does not silently lower a gate or reinterpret unknown labels.

## Key outputs

Each run preserves:

- `metrics.json` — state/risk/stage training and horizon metrics;
- `v45_protocol.json` — graph/split/source-hash contract;
- `v45_release_gate.json` — fail-closed evidence decision;
- `lstm_statistics.json`, `gnn_lstm_statistics.json` — coverage/abstention and campaign bootstrap;
- `*_verified_incidents.json` — model-specific post-hoc compromise alignment when verified manifests are supplied;
- checkpoint and prediction `.npz` files with hashes/provenance.

## Claims boundary

V45 supplies the code path needed to test the SIH forecasting claim correctly. Until a newly reserved final campaign actually passes these gates, do **not** report FPR ≤1%, recall ≥80%, verified warning lead time, supervised stage accuracy or market-ready autonomous blocking as achieved results.
