# Krishna Defence / Garuda AI — SIH26153 Architecture (2-page source)

## Page 1 — World-model forecasting architecture

### Objective

Garuda AI models a computer network as an evolving graph and forecasts future network states rather than treating every flow as an independent benign/malicious classification. The current strict V46 research path uses only network telemetry available at inference time and rolls the learned state dynamics 10/20/30/40 seconds forward.

### Offline telemetry pipeline

**Input** → raw PCAP or source-labelled flow telemetry → integrity validation → 10-second time buckets → directed network graph → bounded feature tensor.

The additive V46 state vector has **34 flow + packet telemetry dimensions** covering the SIH statement:

- flow/byte/packet counts and duration;
- SYN, ACK, RST, FIN, PSH and URG fractions;
- backward-packet ratio and TCP/UDP proportions;
- IAT mean, variance and maximum;
- TCP receive-window statistic;
- TTL mean/variance and IP fragmentation;
- payload-size mean/variance/maximum;
- destination-port diversity and sequential/non-sequential port transitions;
- retransmission fraction/count;
- explicit feature-availability flags.

Source/destination endpoints form graph structure; learned endpoint IDs are not used as shortcuts. Raw PCAP does **not** imply attack truth: labels remain unknown until an explicit annotation source is attached. Incomplete packet evidence is never imputed; an affected 10-second state is excluded and audited.

### Learned state transition

Observed context: **8 × 10-second graph states (80 s)**.

World-model candidates:

1. **Residual LSTM** — temporal state-transition model.
2. **Directed GNN + LSTM** — graph message passing followed by temporal state learning.

Both start at exact persistence and learn a residual future-state change. State parameters are optimized only for future-state error. Epoch 0 persistence participates in model selection; a model that cannot beat validation persistence is not promoted to risk training.

The model autoregressively predicts four future states:

`S(t) → S(t+10) → S(t+20) → S(t+30) → S(t+40)`

This directly implements a learned approximation of network transition dynamics `P(S(t+1) | S(t))`. The runtime output is a future network-state trajectory, not merely a current-flow label.

### Risk and progression heads

After the state checkpoint passes its validation gate, state parameters are frozen. A separate risk head estimates malicious-traffic evidence across future horizons. Calibration and alert threshold selection use validation traffic only; the target operating budget is **FPR <= 1%**.

A separate five-tactic stage head is available only with explicit reviewed supervision:

- Reconnaissance — MITRE TA0043
- Initial Access — TA0001
- Lateral Movement — TA0008
- Command & Control — TA0011
- Exfiltration — TA0010

Missing stage truth remains unknown rather than becoming a negative label.

### Explainability

For a forecast, Garuda computes local **gradient × input** feature attribution over the observed history. The dashboard can rank the traffic features driving the predicted future risk/state. These values are model sensitivities, not causal proof or SHAP values.

---

## Page 2 — Evidence discipline, defence integration and deployment

### Evaluation contract

Campaigns are separated into train / validation / final-test groups. Final-test data is not used for normalization, class weighting, state checkpoint selection, calibration or threshold selection. Unknown labels are masked.

The benchmark compares models with equal observed evidence:

- Logistic Regression — non-world-model risk baseline
- Residual LSTM — temporal world-model baseline
- GNN + LSTM — topology-aware temporal world model
- Persistence — state-forecast baseline

Reported evidence includes state MSE versus persistence; 10/20/30/40-second risk metrics; per-family precision/recall/FPR/F1; clean-history false alerts; seed sensitivity; coverage/abstention; and, only when independently verified incident timestamps exist, pre-compromise lead time.

### Current V46 diagnostic boundary

The first 34-feature V46 PCAP diagnostic uses reused CIC-IDS2018 campaigns and weak schedule-assisted labels, so it is **not final SIH evidence**. All three seeds beat persistence on the web validation campaign, but cross-family botnet/infiltration test state MSE is worse than persistence. No model passes the FPR <=1% / recall >=80% attack gate. There are no clean-history future-positive test examples and no verified compromise timestamps, so pre-compromise lead time is not claimed. Supervised MITRE metrics are also not claimed.

This negative evidence is intentional: the pipeline fails closed rather than turning an exposed holdout into a success claim.

### Three-tier defence path

**Garuda AI** produces forecast evidence and explanations. Defence actions remain separately governed:

- **Arjuna** — reviewed known-attack rules and reversible blocking.
- **Krishna** — unknown/unsupported forecast lane; stores evidence for review and future research rather than silently converting novelty into a known signature.
- **Sudarshana** — operator-scoped lockdown controls for an owned lab environment, with signed policy, TTL, audit trail and revoke/kill-switch behavior.

Forecast metrics alone never approve autonomous enterprise containment. Unsupported traffic can abstain / return insufficient evidence.

### Enterprise / Critical Information Infrastructure applicability

The prototype is fully local/offline for inference; no cloud API is required. It provides schema checks, model/checkpoint hashes, bounded inputs, authentication, loopback-by-default service exposure, signed temporary response policy, tenant-aware audit concepts and reversible controls. Production deployment still requires sensor integration, identity/TLS, protected model registry, load/failure testing, independent security review and organization-specific policy approval.

### Release-grade evidence still required

Before claiming verified predictive defence:

1. reserve genuinely new campaign(s) before inspection;
2. prepare compatible flow + packet telemetry under the same frozen schema;
3. verify attack onset, successful compromise time and stage-positive/negative intervals independently;
4. obtain clean-history future-positive incidents;
5. run fixed seeds without test-guided tuning;
6. require test state forecasting to beat persistence;
7. require supported held-out families to satisfy FPR <=1% and recall >=80%;
8. report positive measured pre-compromise lead time and supervised stage metrics.

**Current status:** strong world-model software prototype and reproducible research pipeline; verified pre-compromise production forecasting remains an open evidence gate.
