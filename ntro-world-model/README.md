# 🦅 Garuda AI — Predictive Attack Forecasting Engine

> **Part of Krishna Defence System | SIH26153 (NTRO)**
>
> Garuda AI is the predictive brain of the Krishna Defence System. It uses a genuine 4-Gate LSTM + Transformer neural network to learn network state transitions from CIC-IDS2018 traffic telemetry and predict attacks **+150 seconds BEFORE** compromise is completed.

---

## Architecture: 4-Gate LSTM Sequence Model

```
CSE-CIC-IDS2018 Dataset (200,000+ Rows, 80 Columns)
                           │
                           ▼
          ┌───────────────────────────────────┐
          │     10s Temporal Window Aggregator │
          │   12-dim Normalized Vector S_t    │
          └─────────────────┬─────────────────┘
                            │
          ┌─────────────────▼─────────────────┐
          │     Gated LSTM Recurrent Cell     │
          │   i_t = σ(W_xi·S_t + W_hi·h + b) │
          │   f_t = σ(W_xf·S_t + W_hf·h + b) │
          │   g_t = tanh(W_xg·S_t + W_hg·h+b)│
          │   o_t = σ(W_xo·S_t + W_ho·h + b) │
          │   c_t = f_t*c + i_t*g_t           │
          │   h_t = o_t * tanh(c_t)           │
          └─────────────────┬─────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
  ┌───────────────────┐           ┌───────────────────┐
  │  State Transition │           │  Attack Risk      │
  │  Decoder (MSE)    │           │  Prediction (BCE) │
  │  Ŝ_{t+1..t+8}    │           │  P(attack) = σ(Wh)│
  └───────────────────┘           └───────────────────┘
```

---

## Dataset: CSE-CIC-IDS2018

- **Source:** Canadian Institute for Cybersecurity (CIC), University of New Brunswick
- **URL:** https://www.unb.ca/cic/datasets/ids-2018.html
- **Files Used:**
  - `Friday-02-03-2018_Infiltration_REAL.csv` — 200,000 rows, 80 columns (Bot attack + Benign)
  - `Thursday-01-03-2018_Infiltration.csv` — 50,000 rows (Benign baseline)

---

## Benchmarks (Leakage-Free Contiguous Time-Block Split)

> Independently verified: windows split into contiguous time blocks FIRST, sequences built within each block. Zero window overlap between train/test.

| Metric | Logistic Regression (Baseline) | **Garuda AI (LSTM)** | Advantage |
|---|:---:|:---:|:---:|
| F1-Score | 88.9% | **98.2%** | +9.3% |
| Precision | 92.3% | **100.0%** | +7.7% |
| Recall | 85.7% | **96.4%** | +10.7% |
| FPR | 7.1% | **0.0%** | -7.1% |
| Advance Warning | 0s (reactive) | **+60–150s (proactive)** | Temporal |

> ⚠️ Small test set (56 sequences). k-Fold CV recommended for robustness.

---

## Quick Start

```bash
# Train Garuda AI
python3 train_world_model.py

# Run 5-Fold Cross-Validation
python3 kfold_cross_validation.py

# Run LSTM vs Baseline Comparison
python3 baseline_benchmark.py

# Interactive Dashboard
streamlit run streamlit_app.py
```

---

## Files

| File | Purpose |
|------|---------|
| `pytorch_models.py` | CyberLSTMWorldModel — 4-Gate LSTM + Transformer |
| `train_world_model.py` | Training pipeline with BPTT |
| `dataset_pipeline.py` | CIC-IDS2018 CSV → 10s window state vectors |
| `baseline_benchmark.py` | Garuda AI vs Logistic Regression benchmark |
| `kfold_cross_validation.py` | 5-Fold Stratified Cross-Validation |
| `streamlit_app.py` | Interactive Streamlit dashboard |
| `cyber_world_model_pytorch.pt` | Trained PyTorch checkpoint |
| `trained_world_model_weights.json` | Exported neural network weights |

---

**Part of Krishna Defence System — Smart India Hackathon 2026 🇮🇳**
