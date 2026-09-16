# Krishna Defence — release evidence

This is the judge-facing evidence index for SIH26153. It separates current controlled evidence from historical experiments.

## Strongest current result: V48 unseen-family generalisation

Authoritative GitHub Actions run: `35107130823`.

The frozen Garuda alert fusion was selected without reserve-family metrics. X-IIoTID family labels were canonicalized before splitting, all V47-published families remained development-only, and the untouched reserve set was limited to `exploitation` and `c&c`.

| Reserve family | Recall mean ± SD | FPR mean ± SD | Precision mean | F1 mean | Gate across seeds 42/43/44 |
|---|---:|---:|---:|---:|---|
| Exploitation | **91.88% ± 0.60 pp** | **0.390% ± 0.042 pp** | 97.08% | 94.41% | **PASS 3/3** |
| Command & Control (`c&c`) | **87.63% ± 2.69 pp** | **0.366% ± 0.000 pp** | 97.02% | 92.08% | **PASS 3/3** |

Frozen configuration: 75% `known_attack_transfer` + 25% `transition_energy`, benign policy budget 0.25%, config SHA-256 `4b1a25da56bfd7b7e07e9ae542cf9993485be8437924d479536415508889ad6a`.

Current defensible claim:

> A frozen Garuda fusion generalized to two public-dataset attack families excluded from model fitting, calibration, policy selection and fusion-score development, while satisfying the project gate of FPR <=1% and recall >=80% across all three seeds.

Full evidence: [`docs/release/V48_RESULTS.md`](docs/release/V48_RESULTS.md).

## V52 temporal evidence status

V52 adds fail-closed timestamp/provenance machinery for CICAPT-IIoT2024 attack-step evaluation. A byte-preserved, commit-pinned third-party copy of `attack_info.csv` is stored with provenance, accepted directly with publisher-style headers, and independently cross-checked against a Sandcat event record.

That recovered source is deliberately classified `third_party_git_pinned_copy` with `publisher_verified = false`. It is development-grade attack-step timeline evidence; it is **not** publisher-authenticated successful-compromise truth.

Therefore V52 does not yet promote a verified successful-compromise lead-time claim. Full boundary: [`docs/release/V52_CICAPT_TIMELINE.md`](docs/release/V52_CICAPT_TIMELINE.md).

## Release-status matrix

| Requirement | Current status | What is supported |
|---|---|---|
| State forecasting/world-model approximation | Supported | Autoregressive state-dynamics models and persistence gating are implemented. |
| Controlled unseen-family generalisation | **Passed on V48 reserve benchmark** | Two untouched X-IIoTID reserve families passed <=1% FPR / >=80% recall on all three seeds. |
| Verified pre-attack timing machinery | Implemented | V52 can audit warnings strictly before independently timestamped attack steps. |
| Publisher-verified compromise lead time | **Not yet proven** | Recovered CICAPT timeline is third-party commit-pinned, not publisher-verified successful-compromise evidence. |
| Supervised MITRE progression quality | **Not release-proven** | Stage infrastructure exists, but independently validated stage-transition performance remains a separate evidence gate. |
| Automatic enterprise containment | **Not approved** | Lab controls and scoped operator actions are not production authorization. |

## Historical record

Superseded V8–V50 reports, old console reports, earlier host/service-graph failures, and other exploratory evidence are preserved under [`docs/archive/`](docs/archive/). They are intentionally not deleted. Keeping failed experiments visible protects reproducibility while preventing stale metrics from being mistaken for the current release.

## Claim boundary

Do not describe V48 as proof of a truly undisclosed real-world zero-day, verified compromise prevention, or enterprise readiness. Do not describe forecast horizon as measured warning lead time. Do not describe the recovered V52 third-party timeline as publisher-authenticated. Historical host/service-graph results are exploratory evidence and are not the current release benchmark.
