# Krishna Defence — release evidence

This is the judge-facing evidence index for SIH26153. It separates reproducible release evidence from exploratory/historical experiments and keeps failed or insufficient-support tests visible.

## Strongest independent attack-generalisation evidence: V63 UNSW-NB15 conservative audit

Authoritative GitHub Actions run: `35523775769`.

The frozen Garuda scorer was evaluated on two independently selected UNSW-NB15 cyber-range family/episode holdouts (`backdoor`, `analysis`). Episode selection used timestamps/support only; UNSW test metrics were not used for fusion selection. Seeds: 42/43/44.

| Measure | Result |
|---|---:|
| Raw macro recall | **98.6772%** |
| Raw macro FPR | **0.28708%** |
| Conservative worst per-seed Wilson-95 recall lower bound | **87.3949%** |
| Conservative worst per-seed Wilson-95 FPR upper bound | **0.53596%** |
| Family × seed evaluations | 6 |
| Interval gate | **PASS** |

Support is non-trivial: Backdoor has 315 positive / 9,360 negative test windows; Analysis has 120 positive / 4,379 negative test windows. The conservative confidence-bound view, not a 100% point estimate, is the preferred headline.

## Same-input Logistic Regression baseline: V67

Authoritative GitHub Actions run: `35524682867`.

Both systems receive the same observed network-state history on the same UNSW episodes. Logistic Regression uses train-only imputation/scaling and a clean policy-period threshold. Garuda configuration remains frozen; neither method uses test labels/features for tuning.

| Metric | Logistic Regression | Garuda | Garuda − LR |
|---|---:|---:|---:|
| Recall | 57.7910% | **98.6772%** | **+40.8862 pp** |
| FPR | 0.49032% | **0.28708%** | **−0.20324 pp** |
| Precision | 77.7388% | **91.4804%** | **+13.7416 pp** |
| F1 | 64.8467% | **94.6320%** | **+29.7853 pp** |

Full evidence: [`docs/release/v67_same_input_baseline/RESULTS.md`](docs/release/v67_same_input_baseline/RESULTS.md).

## Real packet + flow telemetry: V68

Authoritative GitHub Actions run: `35524994985`.

The production reader now detects PCAPNG by magic bytes and parses the real hash-pinned CICAPT-IIoT2024 captures even though their filenames end in `.pcap`. A bounded prefix of 200,000 decoded IPv4 packets from each phase was audited. The feature schema contains the SIH-requested flow groups (bytes/packets/duration, TCP flags, protocol mix, bidirectional ratio, IAT mean/variance/max) and packet groups (TTL, TCP window, fragmentation, payload distribution, port-scan sequencing, retransmission).

Observed packet evidence is reported as observed: TTL, TCP-window, payload, IAT and retransmission features were non-zero across all sampled windows; fragmentation was zero in both bounded prefixes and remains zero rather than being fabricated as present.

Full evidence: [`docs/release/v68_cicapt_packet_contract/RESULTS.md`](docs/release/v68_cicapt_packet_contract/RESULTS.md).

## Combined packet+flow state-transition forecasting: V70

Authoritative GitHub Actions run: `35525494762`.

A residual LSTM world model consumes the full combined packet+flow network-state vector built directly from real CICAPT PCAPNG. It trains/validates on Phase 1 only and is evaluated on the separate Phase-2 capture. Phase 2 is excluded from training, normalization, blend selection and early stopping.

| Seed | Garuda Phase-2 MSE | Persistence MSE | Improvement |
|---:|---:|---:|---:|
| 42 | 1.4409611 | 2.0003519 | **27.9646%** |
| 43 | 1.4619979 | 2.0003519 | **26.9130%** |
| 44 | 1.4484663 | 2.0003519 | **27.5894%** |

Mean improvement vs persistence: **27.4890%**, SD **0.5330 pp**, PASS 3/3 seeds. This is state-dynamics evidence, not attack-stage accuracy or warning lead time.

Full evidence: [`docs/release/v70_cicapt_packet_world_model/RESULTS.md`](docs/release/v70_cicapt_packet_world_model/RESULTS.md).

## Stage-label evidence boundary: V69

Authoritative GitHub Actions run: `35525241720`.

The entire CICAPT Phase-2 decoded IPv4 capture (9,461,828 packets) was scanned. All 20 unique publisher-style tactic timestamp windows align to real packet-time windows, but the source metadata still marks them `network_stage_validated=false`. Unique aligned support is only 9 Recon/Discovery, 1 Initial Access, 3 Lateral Movement, 4 Command & Control and 3 Exfiltration windows.

Therefore a five-class publisher-validated MITRE F1 is **not release-supported**. The code fails closed instead of deriving a misleading score from one/few windows.

Full evidence: [`docs/release/v69_cicapt_stage_alignment/RESULTS.md`](docs/release/v69_cicapt_stage_alignment/RESULTS.md).

## Five-stage lifecycle proxy mapping: V73 development evidence

Authoritative GitHub Actions run: `35525990295`.

Because X-IIoTID lifecycle stages are globally campaign-ordered, V73 uses a predeclared **per-stage temporal block holdout**, not a single global chronological split. All five requested lifecycle-stage proxies are present in the held-out set (729 sequences). Seeds 42/43/44 produced the same held-out result:

| Measure | Result |
|---|---:|
| Accuracy | **87.7915%** |
| Macro F1 | **68.3203%** |
| Macro recall | **79.8687%** |
| Macro precision | **64.6423%** |
| Forecast-state F1 gain vs persistence-state mapping | **0.0 pp** |

The aggregate accuracy hides a serious class failure: **Reconnaissance recall is 0/86 = 0%**, with all 86 Reconnaissance sequences mapped to `Initial Access proxy`. Lateral Movement recall is 454/457, C&C is 33/33, Exfiltration is 118/118, and Initial Access proxy is 35/35 but with low precision because it absorbs Reconnaissance.

This is preserved as honest development evidence, not presented as a solved MITRE-stage system. `Exploitation → Initial Access proxy` remains a proxy mapping, and publisher-validated CICAPT stage F1 remains unproven.

Full evidence: [`docs/release/v73_stage_temporal/RESULTS.md`](docs/release/v73_stage_temporal/RESULTS.md).

## Prospective attack-step onset timing: V72 development evidence

Authoritative GitHub Actions run: `35525685873`.

The warning score is prediction-only and its threshold is frozen on Phase 1 before Phase-2 event comparison. Across seeds 42/43/44 the mean Phase-2 alert rate is **0.36643%**, mean event-warning recall is **25.3333%**, and the mean of the per-seed median lead times among warning hits is **269 s (4 min 29 s)**. Coverage is weak and the commit-pinned timeline has `publisher_verified=false`.

This is useful diagnostic evidence that some attack steps can be warned before onset; it is **not** a verified successful-compromise lead-time claim.

Full evidence: [`docs/release/v72_cicapt_attack_step_leadtime/RESULTS.md`](docs/release/v72_cicapt_attack_step_leadtime/RESULTS.md).

## Release-status matrix

| Requirement | Current status | What is supported |
|---|---|---|
| Learned network-state transition dynamics | **Supported** | Multi-step residual LSTM state forecasting; V70 beats persistence on separate CICAPT Phase-2 capture across all three seeds. |
| Both flow-level and packet-level telemetry | **Supported** | V68 real-PCAPNG evidence plus V70 combined packet+flow world-model consumption. |
| Independent attack generalisation | **Supported with bounded claim** | V63 UNSW audit passes conservative confidence-bound gate on two held-out family/episodes. |
| Same-feature Logistic Regression benchmark | **Supported** | V67 shows large recall/F1 improvement and lower FPR on the same independent protocol. |
| Explainability | Supported in system | SHAP/evidence-attribution infrastructure is implemented; this index does not claim a new quantitative explainability score. |
| Five-stage attack mapping | **Partial / needs improvement** | V73 produces a real five-stage proxy metric, but macro F1 is 68.32%, Recon recall is 0%, and forecast-state mapping does not beat persistence. Exact publisher-validated MITRE F1 remains unsupported. |
| Prospective pre-attack-step warning | **Partial / needs improvement** | V72 has a low alert rate and positive lead-time hits but only 25.33% mean event coverage. |
| Publisher-verified successful-compromise lead time | **Not proven** | Available recovered CICAPT timeline is third-party commit-pinned and not publisher-authenticated successful-compromise truth. |
| Automatic enterprise containment | **Not approved** | Lab controls and scoped operator actions are not production authorization. |

## Historical / diagnostic failures kept visible

Earlier V8–V54 failures, the V65 Worms seed-instability result, V66/V66b preparation failures, V71/V71b unsupported global stage splits, and other exploratory evidence are preserved rather than deleted. V65 is especially important: two outer seeds detected 21/21 Worms windows while one detected only 1/21, exposing seed instability. V66/V66b never reached fresh Fuzzers scoring, so Fuzzers remains unmeasured rather than being called pass/fail.

## Claim boundary

Do not describe these experiments as proof of a truly undisclosed real-world zero-day, guaranteed compromise prevention, production enterprise readiness, or universal accuracy. Do not equate forecast horizon with measured warning lead time. Do not present the V72 third-party timeline as publisher-authenticated. Do not present an `Initial Access proxy` derived from X-IIoTID `Exploitation` as exact MITRE Initial Access truth. Do not use V73 aggregate accuracy without its macro-F1, zero-Recon-recall and persistence-parity limitations. Prefer exact counts, multi-seed results and confidence bounds over perfect-looking point estimates.
