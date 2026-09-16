# Krishna Defence / Garuda AI — Max 5-slide SIH content

> Use only verified numbers from the cited V46/V15 result files. Do not convert the 40-second forecast horizon into “40 seconds before compromise.”

## Slide 1 — From intrusion detection to predictive cyber defence

**Problem:** Traditional IDS classifies current flows. An infiltration unfolds over time.

**Our approach:** Garuda AI learns the evolving network state and autoregressively forecasts the next **10 / 20 / 30 / 40 seconds**.

Visual flow:

`PCAP / Flow telemetry → 10s network graph → LSTM / GNN+LSTM world model → future state rollout → risk + stage + explanation → reviewed defence`

Key line: **We model state transition dynamics first; attack-risk decisions are a separate gated layer.**

## Slide 2 — PS-complete network state + world model

**34 flow + packet features** now explicitly cover the challenge feature contract:

- all TCP flags including PSH/URG;
- packet/byte/flow counts, duration, bidirectional ratio;
- IAT mean/variance/max;
- TTL mean/variance, TCP window, fragments;
- payload distribution;
- destination-port diversity + sequential/random port transitions;
- retransmission fraction/count.

Architecture:

- 8 observed 10-second graph windows = 80 s history
- residual LSTM and directed GNN+LSTM
- 4-step autoregressive future-state rollout
- persistence is epoch-0 baseline
- state checkpoint selected on validation MSE only
- separate calibrated risk head
- optional five-stage MITRE head only with explicit stage supervision
- gradient×input feature attribution

## Slide 3 — Evidence-first evaluation, not a static classifier demo

**Benchmark:** Logistic Regression vs LSTM vs GNN+LSTM + persistence.

**Strict protocol:** campaign separation, unknown ≠ benign, validation-only threshold/calibration, fixed seeds 42/43/44, no best-seed promotion.

First V46 34-feature diagnostic:

| Model | State result / risk result |
|---|---|
| LSTM | validation state improves 36.95% vs persistence; cross-family test state MSE 0.02230 vs persistence 0.01829 → **does not generalise yet** |
| GNN+LSTM | validation improves 34.17%; test MSE 0.02326 vs 0.01829 → **does not generalise yet** |
| Logistic regression | recall 94.37%, but FPR **98.25%** → unusable |
| GNN+LSTM risk | FPR mean 3.51%, recall mean 4.69% → low-alert but misses attacks |

**Result:** current reused/weak-label diagnostic intentionally fails the release gate. That tells us the remaining bottleneck is cross-campaign generalisation/ground truth, not missing UI or a larger model.

## Slide 4 — Interpretable three-tier proactive defence

**Garuda AI** — forecast trajectory, future-risk timeline, driving features, supported MITRE stage.

**Arjuna** — known/reviewed attack enforcement.

**Krishna** — unsupported/novel forecast lane; preserves evidence and abstains where confidence/support is insufficient.

**Sudarshana** — scoped operator-approved lockdown with signed policy, TTL, audit and revoke/kill switch in the lab.

Demo panels:

- live 0–100 risk gauge
- 10/20/30/40s timeline
- graph/topology view
- top contributing telemetry features
- stage or “insufficient evidence”
- reversible defence decision/audit trail

Safety boundary: **forecast confidence never directly equals production authorization.**

## Slide 5 — What is proven, and the national-level evidence gate

**Implemented now**

- open-source/offline software path
- raw PCAP + flow feature extraction
- graph world model + autoregressive future states
- LR/LSTM/GNN+LSTM benchmark
- explainability
- five-stage supervised-head capability
- packet-integrity audit + source hashes
- fail-closed release gate
- audited local response controls

**Next evidence gate before final claim**

1. truly new predeclared campaigns;
2. independently verified attack onset / compromise outcomes;
3. reviewed five-stage positive + negative intervals;
4. clean-history future-positive incidents;
5. state model beats persistence on final campaign;
6. per-family **FPR <=1% + recall >=80%** with sufficient support;
7. positive verified pre-compromise lead time.

Closing message: **Krishna Defence is designed as a predictive cyber-defence world model; V46 now covers the requested telemetry and evaluation contract, while the final claim remains evidence-gated rather than fabricated.**
