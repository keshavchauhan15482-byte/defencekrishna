# 🦅 Garuda AI — Technical Architecture Specification
## Predictive Attack Forecasting Engine — Part of Krishna Defence System
**Problem Statement ID:** SIH26153 | **Category:** Software / Critical Information Infrastructure (CII) Defense

---

### 1. Executive Architecture Summary
We present **Garuda AI**, the predictive attack forecasting engine within the Krishna Defence System. It uses an AI World Model architecture that learns network state-transition dynamics from dual-level network telemetry and forecasts multi-step attacker progression before compromise completes.

### 2. Full CSE-CIC-IDS2018 Dataset & State-Space Representation
The computer network environment is ingested from full 80-column CSE-CIC-IDS2018 flow records and aggregated into discrete 10-second temporal state windows $S_t \in \mathbb{R}^{12}$:
1. `syn_ack_ratio` (SYN / ACK count imbalance)
2. `fin_rst_ratio` (Teardown & reset anomaly)
3. `iat_mean_ms` (Flow Inter-Arrival Time mean)
4. `iat_variance` (Flow IAT jitter)
5. `bytes_per_flow` (Payload volume)
6. `packets_per_flow` (Packet volume)
7. `ttl_mean` (Mean IP Time-To-Live)
8. `ttl_variance` (TTL variance across subnet hops)
9. `tcp_win_size` (TCP receive window size)
10. `port_scan_entropy` (Destination port access sequence entropy)
11. `fragment_flags` (IP fragmentation flag)
12. `retransmission_rate` (TCP retransmission ratio)

### 3. Gated LSTM Transition Dynamics Formulation
Garuda AI computes latent recurrent state transitions using 4-gate LSTM dynamics:
$$\begin{aligned}
i_t &= \sigma(W_{xi} S_t + W_{hi} h_{t-1} + b_i) \\
f_t &= \sigma(W_{xf} S_t + W_{hf} h_{t-1} + b_f) \\
g_t &= \tanh(W_{xg} S_t + W_{hg} h_{t-1} + b_g) \\
o_t &= \sigma(W_{xo} S_t + W_{ho} h_{t-1} + b_o) \\
c_t &= f_t \odot c_{t-1} + i_t \odot g_t \\
h_t &= o_t \odot \tanh(c_t)
\end{aligned}$$

Future states are unrolled auto-regressively:
$$\hat{S}_{t+1} = W_{\text{dec}} h_t + b_{\text{dec}}$$
$$P(\text{Breach}_{t+1}) = \sigma(W_{\text{risk}} h_t + b_{\text{risk}})$$

### 4. Zero Black-Box Explainability (Perturbation SHAP)
Shapley values are computed by evaluating marginal probability deviations against background reference vectors:
$$\phi_i(S) = f(S) - f(S \setminus \{i\} \cup \{\bar{S}_i\})$$

### 5. Closed-Loop Mitigation Hook
When forward forecast $P(\text{Breach}_{t+k}) \ge 0.60$, an automated pre-breach quarantine signal is dispatched to **Krishna Force & Sudarshana Blockchain** via REST API `POST /__sentinel/predictive-lockdown` to isolate lateral ports before lateral movement completes.
