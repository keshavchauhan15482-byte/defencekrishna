# Garuda AI — Authoritative SIH Evidence Matrix

This file is the judge-facing source of truth for the current SIH evidence pack. Experiments are reported by scope; results from different datasets/protocols are not merged into one synthetic score.

## Approved headline claims

### 1. Learned future network state beats persistence

On the V70 CICAPT-IIoT2024 Phase-2 state-forecasting experiment, the learned forecaster achieved **27.489% lower state MSE than the persistence baseline across three seeds**. This is a state-forecasting result, not an attack-classification accuracy number.

A later X-IIoTID state-forecasting diagnostic independently showed **10.7876% lower state MSE than persistence** (0.44053 vs 0.49380). The two improvements are separate experiments and must not be averaged or combined.

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

### 4. Runtime selection and unsupported-input response fail closed

The localhost runtime resolves its compatible checkpoint through `garuda_v3/bundle_manifest.py` and `garuda_v3/active_runtime_bundle.json`; schema/mode/checkpoint identity are validated and incompatible research artifacts are not silently substituted.

V94 extends that boundary to runtime input support. The currently pinned bundle does **not** contain an integrity-pinned validation-fitted `support_gate.json`, so the integrated runtime reports `UNVERIFIED_RUNTIME_SUPPORT` / `SHADOW_UNRESOLVED`. It may display advisory state/risk output, but stage-specific interpretation and forecast-driven autonomous Arjuna/Krishna/Sudarshana actions are suppressed. A future compatible bundle may enable supported decisions only after a validation-fitted support gate is integrity-pinned.

V94 is a safety/abstention mechanism, **not an attack detector and not a claim that out-of-support traffic is malicious**. Final V94 CI run `35567112947` passed **21 focused safety tests** and **188 full Garuda Python tests** (`OK`, 3 optional-dependency skips), including the pinned-bundle fail-closed assertion.

## External-domain stress tests — preserved failures

These results increase evidence integrity but **do not support a universal cross-domain detector claim**.

| First external source | Recall | FPR | Gate |
|---|---:|---:|---|
| IoT-23 | 69.4512% | 57.9874% | FAIL |
| RT-IoT2022 | 86.9309% | 5.7678% | FAIL (FPR) |
| ToN-IoT V92 | 0.4291% | 37.8880% | FAIL |

The ToN-IoT first-test result is immutable and has source SHA256 `26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974`. See `docs/release/v92_toniot_first_test/RESULTS.md`.

**Engineering consequence:** unseen telemetry domains must enter shadow/abstain/domain-validation mode rather than receiving an unsupported universal-detection guarantee. V94 enforces that conservative response policy in the integrated runtime when support is unresolved.

## Attacker progression / lifecycle stage status

The project has multiple honest diagnostics (V82–V89.1), but the current evidence does **not** justify a release claim of robust unseen-subtype attacker-stage prediction.

Earlier diagnostics:

- V86 learned-future multi-horizon progression macro-F1: **0.4912**
- matched persistence macro-F1: **0.5399**
- V86 development subtype viability: FAIL
- V87 selected alpha=0 and therefore did not prove learned-future contribution; its subtype fold FPR setup also lacked meaningful negative controls.

V89.1 corrected the evaluation protocol with real negative controls, disjoint calibration/threshold/evaluation slices, a ≤1% development FPR budget, and observed-only/persistence/Garuda-future ablations. Authoritative run `35565758743` completed successfully and selected `garuda_future_alpha_1.00` without using the exposed reserve for selection.

V89.1 controlled subtype-CV result:

- Minimum subtype recall: **0.00%**
- Mean subtype recall: **26.7018%**
- Maximum evaluation FPR: **0.9079%**
- Mean evaluation F1: **0.2674**
- Mean evaluation PR-AUC: **0.5195**
- Minimum real-negative controls in a fold: **6,168**
- 80%-recall / 1%-FPR development gate: **FAIL**
- Both tested Lateral Movement leave-subtype-out folds: **0% recall**

The controlled three-way supported-target ablation did show a small learned-future gain: mean supported F1 **0.999009** vs **0.998016** for both observed-only and persistence-future, and mean supported recall **0.998020** vs **0.996040** for persistence-future. This does **not** override the failed subtype-robustness gate. The exposed X-IIoTID reserve is diagnostic only and `fresh_claim_allowed=false`; therefore `eligible_for_progression_release_claim=false` remains authoritative.

Where stage/subtype support is not validated, the UI/runtime must use **Unresolved / Insufficient evidence** rather than presenting a confident MITRE-stage claim.

## Attack-onset lead-time status

V93 corrected the timing audit so the issue timestamp is the **end of the final observed history window**, and attack onsets are deduplicated by exact timestamp. Authoritative run: `35566012885`.

Across seeds 42/43/44:

- Mean labelled attack-onset event recall: **22.6667%**
- Mean Phase-2 alert rate: **0.3660%**
- Detected-case median leads by seed: **287 s / 303 s / 303 s**
- Mean of those per-seed detected-case medians: **297.67 s**
- Detected cases per seed: **6 / 5 / 5**
- Bootstrap/interval claim: **withheld** because the minimum detected-case support (5) was below the required 10 cases per seed.

This is **lead to labelled attack-step onset**, not verified lead to compromise. The audit explicitly records `verified_compromise_ground_truth=false`, `pre_compromise_claim=false`, and `automatic_containment_claim=false`.

Do **not** claim verified pre-compromise prediction yet. A defensible pre-compromise claim still requires verified successful-compromise timestamps and adequate case support.

## SIH-safe product statement

> Garuda AI is a network world-model prototype that forecasts future network state from traffic telemetry, converts predicted trajectories into risk/progression evidence, and connects that evidence to layered response controls. The project has demonstrated state-forecasting gains over persistence, a high-recall/low-FPR independent-source UNSW replication, millisecond-scale compatible runtime inference, corrected labelled-attack-onset warning evidence, and a fail-closed runtime support policy. Cross-domain stress tests and controlled subtype evaluation also show that universal portability and robust unseen-subtype stage prediction are not yet solved, so unsupported inputs remain advisory/shadow-mode rather than silently overclaimed.

## Defense architecture wording

- **Arjuna:** policy/enforcement path for validated known/reviewed attack evidence; V94 suppresses forecast-driven autonomous action when runtime support is unresolved.
- **Krishna:** research/adaptation and unknown-threat triage path; stores evidence and supports controlled model evolution, but unknown forecasts remain shadow-only unless both support and evidence gates approve autonomy.
- **Sudarshana:** scoped signed lockdown/data-protection response for explicitly authorized conditions; not presented as autonomous enterprise enforcement without customer validation.

## Claims that are not approved

Do not put these in the final PPT, video, website headline, or judge answer:

- “100% accurate” or “works on every network.”
- “Universal zero-day detector.”
- “V94 detects unknown attacks/OOD traffic.”
- “Verified pre-compromise prediction” without verified compromise timestamps.
- “MITRE stage prediction validated” for unsupported stages/subtypes.
- “Robust unseen-subtype progression is solved.”
- “Enterprise-ready autonomous blocking.”
- A blended metric that combines V70 27.489% and later ~10.788% state-MSE gains.
- Any retuned IoT-23, RT-IoT2022, or ToN-IoT score presented as a fresh first test.

## Submission positioning

For SIH, the strongest defensible differentiation is the **forecast-first architecture + low-FPR independent-source evidence + measured real-time runtime + corrected attack-onset timing evidence + layered response + explicit uncertainty/evidence governance + fail-closed support handling**. The main remaining research gates are cross-domain portability, robust unseen-subtype progression, and verified compromise-timestamp lead-time evidence—not whether the prototype has meaningful forecasting or operational evidence.
