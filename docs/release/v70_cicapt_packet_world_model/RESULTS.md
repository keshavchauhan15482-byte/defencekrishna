# V70 Real CICAPT Combined Packet+Flow World-Model Forecasting

Authoritative GitHub Actions run: `35525494762` (`V70 CICAPT packet+flow world-model benchmark`). Status: **SUCCESS**.

## Contract

- Real, hash-verified CICAPT-IIoT2024 PCAPNG captures are parsed with the production packet reader.
- The state vector uses the full SIH flow+packet feature schema from `garuda_v3.ps_complete.FEATURES`.
- Each state window is 10 seconds; history is 8 windows and future rollout is 4 windows (40-second state forecast).
- The benchmark uses a bounded prefix of **2,000,000 decoded IPv4 packets from each phase**.
- Phase 1 is used for chronological training/validation only, with a 12-sequence embargo.
- Phase 2 is a separate capture and is **not** used for training, normalization, blend selection or early stopping.
- Three independent outer seeds are evaluated: 42, 43, 44.
- Metric: scaled future-state MSE versus persistence (`future state = last observed state`).

## Results

| Seed | Phase-2 Garuda MSE | Persistence MSE | Improvement vs persistence | Phase-2 gate |
|---:|---:|---:|---:|---|
| 42 | 1.4409611 | 2.0003519 | **27.9646%** | PASS |
| 43 | 1.4619979 | 2.0003519 | **26.9130%** | PASS |
| 44 | 1.4484663 | 2.0003519 | **27.5894%** | PASS |

Three-seed mean Phase-2 improvement versus persistence: **27.4890%**.

- SD across seeds: **0.5330 percentage points**.
- Minimum seed improvement: **26.9130%**.
- Phase-2 state gate: **PASS 3/3 seeds**.
- Phase-1 validation mean improvement versus persistence: **39.2771%**, also PASS 3/3.

The validation-selected blend was `alpha=1.0, trend_beta=0.0` for all three seeds; that choice was made without Phase-2 metrics.

## Claim boundary

This is direct evidence that a learned temporal world model consumes the combined packet+flow state representation and predicts future network state better than persistence on a separate CICAPT experiment-phase capture. It is **not** attack-stage F1, attack-warning lead time, successful-compromise prevention, or production zero-day proof.
