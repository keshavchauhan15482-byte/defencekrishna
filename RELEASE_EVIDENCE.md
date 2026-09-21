# Krishna Defence / Garuda AI — Release Evidence

**Authoritative judge-facing evidence:** [`docs/release/FINAL_SIH_EVIDENCE.md`](docs/release/FINAL_SIH_EVIDENCE.md)

This root index intentionally stays short so older exploratory metrics cannot be mistaken for current release evidence. Different experiments and datasets are not blended into one synthetic accuracy score.

## Current strongest evidence

| Evidence | Current result | Scope |
|---|---:|---|
| CICAPT-IIoT2024 V70 learned state forecast vs persistence | **27.489% lower MSE**, 3/3 seeds | State forecasting; separate Phase-2 capture |
| Later X-IIoTID state diagnostic | **10.7876% lower MSE** | Separate experiment; do not blend with V70 |
| UNSW-NB15 V88 independent-source Garuda recall | **98.6772%** | Two independently selected family episodes; 3 seeds/family |
| UNSW-NB15 V88 independent-source Garuda FPR | **0.2871%** | Same protocol as recall above |
| UNSW-NB15 V88 Garuda F1 | **94.7874%** | Same-input comparison |
| Same-input LR FPR / F1 | 11.6544% / 57.6993% | LR recall was 100%; Garuda's advantage is much lower FPR + higher precision/F1 |
| V90 compatible runtime forecast latency | **2.86–3.01 ms mean; 2.92–3.08 ms p95** | In-process GitHub-hosted CPU lab benchmark |
| V90 compatible runtime throughput | **332–349 calls/s** | Sequential, forecast-only, no HTTP overhead |
| V90 max process RSS | **44.99 MiB** | Same lab benchmark |
| V93 corrected labelled attack-onset recall | **22.6667% mean** | Attack-step onset only; not verified compromise prediction |
| V93 detected-case median lead | **287 / 303 / 303 s** | Per seed; CI withheld because detected support was only 6/5/5 cases |
| V94 runtime support safety | **21 focused + 188 full tests PASS** | Unsupported/unverified runtime inputs remain advisory; autonomous forecast response is suppressed |

Detailed V88 evidence: [`docs/release/v88_final_independent_source/RESULTS.md`](docs/release/v88_final_independent_source/RESULTS.md)  
Detailed V90 evidence: [`docs/release/v90_runtime_performance/RESULTS.md`](docs/release/v90_runtime_performance/RESULTS.md)  
V93 corrected lead-time run: `35566012885`  
V94 final runtime-support CI run: `35567112947`

## Cross-domain first-test stress results

These failures are preserved and are **not** retuned into fresh successes:

| Source | Recall | FPR | Gate |
|---|---:|---:|---|
| IoT-23 | 69.4512% | 57.9874% | FAIL |
| RT-IoT2022 | 86.9309% | 5.7678% | FAIL |
| ToN-IoT V92 | 0.4291% | 37.8880% | FAIL |

ToN-IoT first-test source SHA256: `26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974`.  
Detailed V92 record: [`docs/release/v92_toniot_first_test/RESULTS.md`](docs/release/v92_toniot_first_test/RESULTS.md)

These results mean universal cross-domain portability is **not proven**. Unsupported telemetry domains must be treated as shadow/abstain/domain-validation cases rather than receiving an unsupported guarantee. V94 implements this fail-closed response policy in the integrated runtime; support abstention itself is not attack detection.

## Controlled attacker-progression boundary

V89.1 is now complete; it no longer has “pending” status. Authoritative run: `35565758743`.

Selected controlled variant: `garuda_future_alpha_1.00`.

- Minimum subtype recall: **0.00%**
- Mean subtype recall: **26.7018%**
- Maximum evaluation FPR: **0.9079%**
- Mean subtype-CV F1: **0.2674**
- Mean subtype-CV PR-AUC: **0.5195**
- Minimum real-negative controls per fold: **6,168**
- Both tested Lateral Movement leave-subtype-out folds: **0% recall**
- 80%-recall / 1%-FPR development gate: **FAIL**

A narrow supported-target ablation did show learned-future F1 **0.999009** vs **0.998016** for both observed-only and persistence-future, but this does not override the failed subtype robustness gate. The exposed X-IIoTID reserve is diagnostic only, so robust unseen-subtype progression remains **not release-supported** and `fresh_claim_allowed=false`.

## Corrected lead-time / pre-compromise boundary

V93 corrected the issue time to the end of the final observed history window and exact-timestamp deduped attack onsets. Across three seeds it measured **22.6667% mean labelled attack-onset event recall**, **0.3660% mean Phase-2 alert rate**, and detected-case median leads of **287 / 303 / 303 seconds**. Detected support was only **6 / 5 / 5 cases**, so the interval claim was correctly withheld.

This is **lead to labelled attack-step onset**, not lead to verified compromise. Verified successful-compromise lead time remains unproven.

## Runtime boundary

The localhost demo uses a schema-compatible active bundle resolved by `garuda_v3/bundle_manifest.py` and `garuda_v3/active_runtime_bundle.json`. Research checkpoints are not silently substituted into the live runtime when their feature/schema contract differs.

V94 adds a second fail-closed boundary for runtime support. The currently pinned bundle has no integrity-pinned validation-fitted `support_gate.json`, so the integrated runtime reports `UNVERIFIED_RUNTIME_SUPPORT` / `SHADOW_UNRESOLVED`: advisory state/risk may still be displayed, but stage-specific interpretation and forecast-driven autonomous Arjuna/Krishna/Sudarshana action are suppressed. V94 final CI passed 21 focused safety tests and 188 full Garuda tests (`OK`, 3 optional-dependency skips).

## Never claim

- universal zero-day detection or 100% accuracy;
- that V94 support abstention is itself attack/OOD detection;
- verified pre-compromise prediction without verified compromise timestamps;
- fully validated MITRE stage prediction where subtype/stage evidence is insufficient;
- robust unseen-subtype progression as solved;
- enterprise-ready autonomous containment;
- a blended number combining unrelated V70 and later ~10.788% state-forecast experiments;
- any retuned IoT-23, RT-IoT2022, or ToN-IoT score as a fresh first test.
