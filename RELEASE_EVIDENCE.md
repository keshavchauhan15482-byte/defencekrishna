# Krishna Defence / Garuda AI — Release Evidence

**Authoritative judge-facing evidence:** [`docs/release/FINAL_SIH_EVIDENCE.md`](docs/release/FINAL_SIH_EVIDENCE.md)

This root index intentionally stays short so older exploratory metrics cannot be mistaken for current release evidence. Different experiments and datasets are not blended into one synthetic accuracy score.

## Current strongest evidence

| Evidence | Current result | Scope |
|---|---:|---|
| CICAPT-IIoT2024 V70 learned state forecast vs persistence | **27.489% lower MSE**, 3/3 seeds | State forecasting; separate Phase-2 capture |
| UNSW-NB15 V88 independent-source Garuda recall | **98.6772%** | Two independently selected family episodes; 3 seeds/family |
| UNSW-NB15 V88 independent-source Garuda FPR | **0.2871%** | Same protocol as recall above |
| UNSW-NB15 V88 Garuda F1 | **94.7874%** | Same-input comparison |
| Same-input LR FPR / F1 | 11.6544% / 57.6993% | LR recall was 100%; Garuda's advantage is much lower FPR + higher precision/F1 |
| V90 compatible runtime forecast latency | **2.86–3.01 ms mean; 2.92–3.08 ms p95** | In-process GitHub-hosted CPU lab benchmark |
| V90 compatible runtime throughput | **332–349 calls/s** | Sequential, forecast-only, no HTTP overhead |
| V90 max process RSS | **44.99 MiB** | Same lab benchmark |

Detailed V88 evidence: [`docs/release/v88_final_independent_source/RESULTS.md`](docs/release/v88_final_independent_source/RESULTS.md)  
Detailed V90 evidence: [`docs/release/v90_runtime_performance/RESULTS.md`](docs/release/v90_runtime_performance/RESULTS.md)

## Cross-domain first-test stress results

These failures are preserved and are **not** retuned into fresh successes:

| Source | Recall | FPR | Gate |
|---|---:|---:|---|
| IoT-23 | 69.4512% | 57.9874% | FAIL |
| RT-IoT2022 | 86.9309% | 5.7678% | FAIL |
| ToN-IoT V92 | 0.4291% | 37.8880% | FAIL |

ToN-IoT first-test source SHA256: `26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974`.  
Detailed V92 record: [`docs/release/v92_toniot_first_test/RESULTS.md`](docs/release/v92_toniot_first_test/RESULTS.md)

These results mean universal cross-domain portability is **not proven**. Unsupported telemetry domains should be treated as shadow/abstain/domain-validation cases rather than receiving an unsupported guarantee.

## Progression / pre-compromise boundary

Robust unseen-subtype attacker progression is not yet release-supported by the completed V82–V87 diagnostics. V86 learned-future progression macro-F1 was 0.4912 vs 0.5399 for persistence, and V87 selected zero learned-future contribution. V89/V89.1 corrects the evaluation protocol with genuine negative controls, separate calibration/threshold/evaluation slices, and explicit observed-only/persistence/Garuda-future ablations; only its controlled output may upgrade this status.

Verified successful-compromise lead time is also not proven. Timing without verified compromise truth must be described as lead to labelled attack onset, not lead to compromise.

## Runtime boundary

The localhost demo uses a schema-compatible, fail-closed active bundle resolved by `garuda_v3/bundle_manifest.py` and `garuda_v3/active_runtime_bundle.json`. Research checkpoints are not silently substituted into the live runtime when their feature/schema contract differs.

## Never claim

- universal zero-day detection or 100% accuracy;
- verified pre-compromise prediction without verified compromise timestamps;
- fully validated MITRE stage prediction where subtype/stage evidence is insufficient;
- enterprise-ready autonomous containment;
- a blended number combining unrelated V70/V86 state-forecast experiments;
- any retuned IoT-23, RT-IoT2022, or ToN-IoT score as a fresh first test.
