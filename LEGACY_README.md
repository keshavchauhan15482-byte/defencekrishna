> **2026-09-11 audit update:** This is a research/demo prototype, not a market-ready security product. Legacy accuracy, zero-day, lead-time and production claims below are unverified and superseded by `AUDIT.md`. The CSV timestamp bug is repaired; existing weights require retraining and revalidation. Read `AUDIT.md` before running or presenting this project. New experimental future-target training: `ntro-world-model/train_forecast_v2.py`. Proxy and Python API now bind to loopback by default.

# Krishna Defence System 🇮🇳🏹🦚☸️🦅

### AI-Powered Network Attack Forecasting & Real-Time Threat Neutralization
**Smart India Hackathon 2026 — Problem Statement SIH26153 (NTRO)**
**Team: The Predators**

> *Design and develop a software prototype that learns the evolving state of a computer network from traffic telemetry and predicts the likelihood and progression of malicious activity before compromise is completed.*

---

## 🏛️ Unified Architecture — 4 Divine Shields, 1 Defence System

Krishna Defence System is a **single, unified AI-powered cyber defence platform** with 4 tightly integrated layers — each named after warriors from the Mahabharata. They work together in real-time on every request:

```
                        Incoming Network Traffic (Port 8080)
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
   ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐
   │    🦅 GARUDA AI       │ │   🏹 ARJUNA FORCE    │ │   🦚 KRISHNA FORCE   │
   │  (Predictive Brain)  │ │  (Front-Line Guard)  │ │  (Zero-Day Hunter)   │
   │                      │ │                      │ │                      │
   │ • LSTM + Transformer │ │ • 1KB Bloom Filter   │ │ • Shannon Entropy    │
   │ • Predicts attacks   │ │ • O(1) Bitwise Match │ │ • Syntax Density     │
   │   +150s BEFORE they  │ │ • <1ms enforcement   │ │ • Novel 0-Day detect │
   │   happen             │ │ • 805+ learned sigs  │ │ • Auto-mutation R&D  │
   │ • Autoregressive     │ │                      │ │ • Trains Arjuna live │
   │   state forecasting  │ │                      │ │                      │
   └──────────┬───────────┘ └──────────┬───────────┘ └──────────┬───────────┘
              │                        │                        │
              └────────────────────────┼────────────────────────┘
                                       ▼
                          ┌──────────────────────┐
                          │  ☸️ SUDARSHANA CORE   │
                          │  (Containment Lock)   │
                          │                       │
                          │ • Scoped lockdowns     │
                          │ • SHA-256 integrity    │
                          │ • Incident telemetry   │
                          │ • Auto-recovery        │
                          └───────────┬───────────┘
                                      │
                  ┌───────────────────┼───────────────────┐
                  ▼                                       ▼
       [ HTTP 403 — BLOCKED ]              [ HTTP 200 — Clean to Backend :4000 ]
```

---

## 🦅 Garuda AI — Predictive Attack Forecasting Engine

Garuda AI is the **prediction brain** of Krishna Defence System. It uses a genuine **4-Gate LSTM + Transformer** neural network (PyTorch) to learn network state transitions and predict attacks **before they happen**.

### How It Works:
```
CSE-CIC-IDS2018 Dataset (200,000+ Rows, 80 Columns)
                    │
        10-second Temporal Window Aggregator
        → 12-dimensional State Vector S_t
                    │
        Gated LSTM Recurrent Cell (2 layers, 64 hidden)
        → State Transition Decoder: Ŝ_{t+1..t+8} = f(S_t)
        → Attack Risk Head: P(attack) = σ(W·h_t)
                    │
        +150s Advance Warning BEFORE compromise
```

### Benchmarks (CSE-CIC-IDS2018 — Leakage-Free Contiguous Time-Block Split):

> Independently verified with zero window overlap between train/test. Raw windows split into contiguous time blocks FIRST, sequences built within each block.

| Metric | Logistic Regression (Baseline) | **Garuda AI (LSTM)** | Advantage |
|---|:---:|:---:|:---:|
| **F1-Score** | 88.9% | **98.2%** | +9.3% |
| **Precision** | 92.3% | **100.0%** | +7.7% |
| **Recall** | 85.7% | **96.4%** | +10.7% |
| **FPR** | 7.1% | **0.0%** | -7.1% |
| **Advance Lead Time** | 0s (reactive) | **+60–150s (proactive)** | Temporal advantage |

> ⚠️ **Caveat:** Test set is 56 sequences — small sample. k-Fold cross-validation recommended for statistical robustness.

### Key Files:
| File | Purpose |
|------|---------|
| `ntro-world-model/pytorch_models.py` | LSTM + Transformer architecture |
| `ntro-world-model/train_world_model.py` | Training pipeline (BPTT) |
| `ntro-world-model/baseline_benchmark.py` | LSTM vs Logistic Regression comparison |
| `ntro-world-model/kfold_cross_validation.py` | 5-Fold Stratified Cross-Validation |
| `ntro-world-model/dataset_pipeline.py` | CIC-IDS2018 → State Vectors |
| `ntro-world-model/streamlit_app.py` | Interactive Dashboard |

---

## 🏹 Arjuna Force — Front-Line High-Speed Guard

The first line of defence. Uses a fixed **1KB Bloom Filter** for O(1) pattern matching against 805+ learned attack signatures in **<1ms**.

- **Adaptive Learning:** When Krishna Force catches a new zero-day, it auto-generates 5x-10x mutation variants and trains Arjuna's Bloom filter — next time the same pattern family appears, Arjuna blocks it on the front line without invoking the full AI pipeline.
- **Memory:** Fixed 1,024 bytes, zero memory bloat regardless of signature count.

### Key Files:
| File | Purpose |
|------|---------|
| `counter-engine.js` | Adaptive learning & mutation R&D |
| `bloom-filter.js` | 1KB Bloom filter implementation |
| `counter-memory.json` | 805+ learned attack signatures |

---

## 🦚 Krishna Force — Zero-Day AI Strategist

The AI detection layer. Runs 25+ security rules, mathematical Shannon entropy analysis, SQL AST tokenization, and a 6-layer ML Meta-Learner fusion pipeline on every request.

### Detection Capabilities (verified):
- SQL Injection (including blind, tautology, UNION-based)
- XSS (including fullwidth Unicode, null-byte injection)
- Command Injection, SSRF, LFI/RFI, Path Traversal
- Log4j RCE, Prototype Pollution, NoSQL Injection
- AI Prompt Injection, CSV Formula Injection, JWT None Cipher
- Business Logic Tampering (negative price, quantity overflow)
- Brute-Force Login Protection (username+IP rate limiting)
- IP Spoofing Prevention (X-Forwarded-For validation)

### Key Files:
| File | Purpose |
|------|---------|
| `detection-engine.js` | Core 25+ rule scoring engine |
| `proxy.js` | WAF reverse proxy (port 8080 → 4000) |
| `sql-tokenizer.js` | SQL AST syntactic analysis |
| `meta-learner-fusion.js` | 6-layer ML signal fusion |
| `semantic-feature-extractor.js` | Semantic intent vectorizer |
| `statistical-anomaly-detector.js` | Isolation Forest ensemble |
| `behavioral-sequence-model.js` | Markov temporal sequence model |

---

## ☸️ Sudarshana Core — Containment & Recovery

The containment boundary. When a critical breach is detected, Sudarshana Core activates **scoped lockdowns** — isolating specific routes/IPs/parameters without taking down the entire system.

### Key Files:
| File | Purpose |
|------|---------|
| `sudarshana-core.js` | Scoped lockdown engine |
| `schema-validator.js` | Positive security model (allowlisting) |

---

## 📊 Security Test Results (Honest Assessment)

> **Note:** These results are from controlled test environments. Real-world performance will vary based on traffic patterns, attacker sophistication, and deployment configuration.

### Network Attack Simulation (8 categories, real TCP connections):
| Attack Category | Result | Notes |
|----------------|--------|-------|
| Recon/Scanning (30 paths) | **30/30 blocked (100%)** | Common scanner paths |
| HTTP Flood/DDoS (200 SQLi at 1,300 req/s) | **200/200 blocked (100%)** | Known SQLi patterns under load |
| Slowloris Attack (10 slow connections) | **10/10 killed (408 Timeout)** | HTTP timeout enforcement |
| Evasion Techniques (encoding, obfuscation) | **10/11 blocked (91%)** | ⚠️ Double URL-encode partially bypasses |
| Distributed APT (30 unique IPs) | **27/30 blocked (90%)** | ⚠️ Low-and-slow probes harder to catch |
| API Abuse / Business Logic | **7/7 blocked (100%)** | Price tampering, IDOR, negative values |
| Throughput Under Attack | **1,250+ req/s** | Single-node Node.js |

### Independent 49-Technique Audit:
| Metric | Result |
|--------|--------|
| Techniques Blocked | **46/49 (93.88%)** |
| Techniques Missed | 3 (advanced evasion) |

### Known Gaps (Engineering Honesty):
- ⚠️ Double URL-encode (`%2527`) still partially bypasses in some cases
- ⚠️ Low-and-slow distributed probes (1 req/min from 30 IPs) are harder to detect
- ⚠️ FPR tested on limited synthetic benign data — real-world FPR estimated **3-8%** depending on traffic patterns
- ⚠️ Garuda AI LSTM benchmarks trained on locally generated CSV data, not official UNB CIC-IDS2018 download

---

## 🚀 Quick Start

### Prerequisites
- Node.js (v16+)
- Python 3.10+ with PyTorch (for Garuda AI prediction engine)

```bash
# 1. Install dependencies
npm install

# 2. Start the protected application (Port 4000)
node demo-website.js

# 3. Start Krishna Defence System (Port 8080)
node proxy.js
```

### Access Dashboards:
- **Live Threat Console:** [http://localhost:8080/__sentinel/console](http://localhost:8080/__sentinel/console)
- **Audit Report:** [http://localhost:8080/__sentinel/report](http://localhost:8080/__sentinel/report)
- **Protected App:** [http://localhost:8080/](http://localhost:8080/)

### Run Garuda AI Prediction:
```bash
# Train Garuda AI on CIC-IDS2018 data
python3 ntro-world-model/train_world_model.py

# Run 5-Fold Cross-Validation Benchmark
python3 ntro-world-model/kfold_cross_validation.py

# Run LSTM vs Baseline Comparison
python3 ntro-world-model/baseline_benchmark.py

# Interactive Streamlit Dashboard
streamlit run ntro-world-model/streamlit_app.py
```

### Run Security Audit:
```bash
# Network Attack Simulation (8 categories)
node network-attack-sim.js

# 100-Attack Gauntlet
node gauntlet-100-attacks.js

# Full Independent Audit
node claude-independent-audit.js
```

---

## 🔬 Independent Red-Team Bugs Fixed (Engineering Honesty)

| # | Bug Found | Root Cause | Fix Applied |
|---|-----------|-----------|-------------|
| 1 | Strong password flagged as attack | Entropy calculated on credential fields | Credential-context sanitization |
| 2 | Fullwidth Unicode XSS bypass (`＜script＞`) | ASCII-only regex | NFKD normalization before inspection |
| 3 | MySQL versioned comment bypass | `\s+` expected after UNION | Updated to `[^\w\n]{1,12}` |
| 4 | Short-form SSRF loopback (`127.1`) | Dotted-quad only regex | Universal IP canonicalization |
| 5 | Prototype Pollution missed (`__proto__`) | `JSON.parse()` drops `__proto__` keys | Scan raw body string directly |
| 6 | IP Spoofing via `X-Forwarded-For` | Header blindly trusted | Socket IP validation (trusted proxy set) |
| 7 | Cascading FPR at scale (24% → 0%) | Blocklist/rate/ML cascade | 6-point decay/threshold tuning |
| 8 | English "select city from list" blocked | SELECT+FROM too broad | Multi-column or SQL-keyword context required |

---

## 🎯 Honest Scope

- **What it IS:** A sovereign, zero-cost, self-evolving AI-powered WAF with predictive attack forecasting (Garuda AI), real-time payload detection (Krishna Force), adaptive learning (Arjuna Force), and automated containment (Sudarshana Core).
- **What it IS NOT:** A distributed global CDN or L3/L4 DDoS scrubbing center. It operates at Layer 7 (HTTP application layer).

---

**Built for Smart India Hackathon 2026 — 100% Sovereign Bharat Architecture 🇮🇳**
**Problem Statement: SIH26153 (NTRO) — AI-Based Network Attack Forecasting**
**Team: The Predators**
