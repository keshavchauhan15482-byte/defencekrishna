# Garuda AI — Authoritative SIH Evidence Matrix

This file is the judge-facing source of truth for the current SIH evidence pack. Experiments are reported by scope; results from different datasets/protocols are not merged into one synthetic score.

## Approved headline claims

### 1. Learned future network state beats persistence

On the V70 CICAPT-IIoT2024 Phase-2 state-forecasting experiment, the learned forecaster achieved **27.489% lower state MSE than the persistence baseline across three seeds**. This is a state-forecasting result, not an attack-classification accuracy number.

A later X-IIoTID state-forecasting diagnostic (V86) independently showed **10.7876% lower state MSE than persistence** (0.44053 vs 0.49380). The two improvements are separate experiments and must not be averaged or combined.

### 2. Independent-source attack replication with low false alarms

V88 evaluated two independently selected UNSW-NB15 attack-family episodes under a frozen same-input protocol, three Garuda seeds per family.

- Garuda macro recall: **98.6772%**
- Garuda macro false-positive rate: **0.2871%**
- Garuda macro precision: **91.2083%**
- Garuda macro F1: **94.7874%**
- Same-input Logistic Regression macro recall: 100.0000%
- Same-input Logistic Regression macro FPR: 11.6544%
- Same-input Logistic Regression macro F1: 57.6993%

The defensible conclusion is: on these independent-source UNSW episodes, Garuda retained very high recall while reducing macro FPR by roughly **40.6×** versus the same-input logistic baseline. Do not claim that Garuda had higher recall than LR.

Authoritative run: `35563992781`. See `docs/release/v88_final_independent_source/RESULTS.md`.

### 3. Measured live-compatible runtime is low latency

V90 measured the checkpoint actually compatible with the localhost graph runtime on a GitHub-hosted Ubuntu CPU runner.

- Forecast-only mean: **2.86–3.01 ms**
- Forecast-only p95: **2.92–3.08 ms**
- Sequential throughput from mean: **332–349 calls/s**
- Forecast + gradient×input explanation mean: **6.17–6.25 ms**
- Maximum process RSS after benchmark: **44.99 MiB**

This is an in-process lab benchmark, not an HTTP/network/customer SLA. Authoritative run: `35564831357`. See `docs/release/v90_runtime_performance/RESULTS.md`.

### 4. Runtime bundle selection is fail-closed

The current localhost runtime resolves its compatible checkpoint through `garuda_v3/bundle_manifest.py` and `garuda_v3/active_runtime_bundle.json`. Schema/mode/checkpoint identity are validated, and incompatible research artifacts are not silently substituted for the live graph runtime. Offline research evidence and deployable runtime compatibility are intentionally separated.

## External-domain stress tests — preserved failures

These results increase evidence integrity but **do not support a universal cross-domain detector claim**.

| First external source | Recall | FPR | Gate |
|---|---:|---:|---|
| IoT-23 | 69.4512% | 57.9874% | FAIL |
| RT-IoT2022 | 86.9309% | 5.7678% | FAIL (FPR) |
| ToN-IoT V92 | 0.4291% | 37.8880% | FAIL |

The ToN-IoT first-test result is immutable and has source SHA256 `26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974`. See `docs/release/v92_toniot_first_test/RESULTS.md`.

**Engineering consequence:** unseen telemetry domains must enter shadow/abstain/domain-validation mode rather than receiving an unsupported universal-detection guarantee.

## Attacker progression / lifecycle stage status

The project has multiple honest diagnostics (V82–V87), but the current evidence does **not** justify a release claim of robust unseen-subtype attacker-stage prediction:

- V86 learned-future multi-horizon progression macro-F1: **0.4912**
- matched persistence macro-F1: **0.5399**
- V86 development subtype viability: FAIL
- V87 selected alpha=0 and therefore did not prove learned-future contribution; its subtype fold FPR setup also lacked meaningful negative controls.

V89/V89.1 was introduced specifically to correct this by using cumulative future-risk/progression targets, real negative controls, disjoint calibration/threshold/evaluation slices, a ≤1% development FPR budget, and observed-only/persistence/Garuda-future ablations. Until that controlled gate produces an approved result, the UI must use **Unresolved / Insufficient evidence** where stage support is not validated.

## Pre-compromise / lead-time status

Do **not** claim verified pre-compromise prediction yet. Historical clean-history evidence was sparse and included a missed future-positive case. Any timing result without a verified successful-compromise timestamp must be described as **lead to labelled attack onset**, not lead to compromise.

## SIH-safe product statement

> Garuda AI is a network world-model prototype that forecasts future network state from traffic telemetry, converts predicted trajectories into risk/progression evidence, and connects that evidence to layered response controls. The project has demonstrated state-forecasting gains over persistence, a high-recall/low-FPR independent-source UNSW replication, and millisecond-scale compatible runtime inference. Cross-domain stress tests also show that universal portability is not yet solved, so unsupported domains are treated as validation/shadow-mode cases rather than silently overclaimed.

## Defense architecture wording

- **Arjuna:** policy/enforcement path for validated known-attack detections.
- **Krishna:** research/adaptation path for unfamiliar or unsupported patterns; stores evidence and supports controlled model evolution.
- **Sudarshana:** scoped lockdown/data-protection response for explicitly authorized breach conditions; not presented as autonomous enterprise enforcement without customer validation.

## Claims that are not approved

Do not put these in the final PPT, video, website headline, or judge answer:

- “100% accurate” or “works on every network.”
- “Universal zero-day detector.”
- “Verified pre-compromise prediction” without verified compromise timestamps.
- “MITRE stage prediction validated” for unsupported stages/subtypes.
- “Enterprise-ready autonomous blocking.”
- A blended metric that combines V70 27.489% and V86 10.788% state-MSE gains.
- Any retuned IoT-23, RT-IoT2022, or ToN-IoT score presented as a fresh first test.

## Submission positioning

For SIH, the strongest defensible differentiation is the **forecast-first architecture + low-FPR independent-source evidence + measured real-time runtime + layered response + explicit uncertainty/evidence governance**. The remaining research gap is cross-domain portability and fully validated attacker progression, not whether the prototype has meaningful forecasting or operational evidence.
