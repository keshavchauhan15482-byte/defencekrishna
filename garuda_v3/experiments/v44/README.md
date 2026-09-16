# Garuda V44 — strict network-only, live-schema runtime regression

V44 is a **new versioned experiment**. It does not rewrite or relabel V15 evidence.

## Contract

- Input schema: `garuda-observed-graph-v3.1`
- 21 canonical network/packet features from `garuda_v3.data.FEATURES`
- 10-second graph windows
- maximum 32 nodes
- 8 observed windows of history
- 4 future windows
- packet-derived IDS2018 graphs; no process/system telemetry
- no synthetic fallback

The checked-in IDS2018 captures were already used during earlier development. Therefore this pipeline can establish **runtime compatibility and regression evidence**, but it is not a newly untouched final test. V44 writes `evidence_scope=development_reused_holdout` and keeps automatic unknown containment disabled.

The strict X-IIoTID/tabular feature selector now lives in `network_feature_gate.py`; it rejects process/system telemetry and fails closed below four genuine network columns without modifying archived V15 sources. The deployable path does not depend on those ad-hoc tabular columns: it trains on the same canonical 21-feature graph schema used by the live Garuda runtime.

## Reproduce

```bash
python -m garuda_v3.experiments.v44.verify_v15_provenance
python -m garuda_v3.experiments.v44.prepare_ids2018_10s
python -m garuda_v3.experiments.v44.label_ids2018_10s
python -m garuda_v3.experiments.v44.preflight
python -m garuda_v3.train \
  --graphs \
  datasets/v44_runtime/labelled/Thursday-22-02-2018.npz \
  datasets/v44_runtime/labelled/Friday-23-02-2018.npz \
  datasets/v44_runtime/labelled/Thursday-01-03-2018.npz \
  datasets/v44_runtime/labelled/Friday-02-03-2018.npz \
  --split-manifest datasets/v44_runtime/split.json \
  --allow-unknown-labels --decoder residual --epochs 20 \
  --history 8 --horizon 4 --stride 8 \
  --calibrate --balance-risk --fpr-budget .01 \
  --evaluation-scope development_reused_holdout \
  --output garuda_v3/artifacts/v44_runtime_regression
```

## Release boundary

A V44 checkpoint is not promoted merely because it trains. A final claim still requires a newly predeclared untouched campaign/day/device/family holdout, verified clean-history positive onset events, and supervised MITRE evidence. Until those gates pass, Krishna unknown-risk actions stay shadow/triage only; reviewed Arjuna exact-known controls and operator-scoped Sudarshana remain separate policy lanes.

The old V15 X-IIoTID metrics are not V44 metrics.
