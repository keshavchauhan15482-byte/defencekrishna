# V92 — ToN-IoT First Untouched External One-Shot

**Authoritative scoring run:** `35565341184`  
**Job:** `106225927963`  
**Pre-access freeze SHA256:** `2705c9fa983c2965caf668d3a410f171fadf814dea11feecccb5c1afc9e8bd39`  
**Pretest model-selection SHA256:** `51e5cc583035a2d1d165568570021fef49ef88f87a4da9120e0ccd1bdd6e30b5`  
**Selected model SHA256:** `f6de446f2efde495fffacbe93d4935e2cdd32b3b50ced632bc9f21b53066ba31`  
**Provenance-only run:** `35565601662`  
**Provenance artifact:** `10623377732`  
**ToN-IoT file SHA256:** `26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974`

## Claim boundary

This is the preserved **first untouched cross-domain transfer** to the ToN-IoT public cyber-range network dataset. Model/feature/threshold selection completed before the first ToN-IoT file access. The subsequent provenance-only run loaded no model and performed no prediction or tuning.

The result is a failure and remains part of the evidence record. ToN-IoT must not be retuned and then relabeled as a fresh test.

## First external result

| Metric | Result |
|---|---:|
| Rows | 211,043 |
| Attack rows | 161,043 |
| Benign rows | 50,000 |
| TP / FN | 691 / 160,352 |
| FP / TN | 18,944 / 31,056 |
| Recall | **0.4291%** |
| False-positive rate | **37.8880%** |
| Precision | **3.5192%** |
| F1 | **0.7649%** |
| PR-AUC | 0.68077 |
| ROC-AUC | **0.32841** |
| 80% recall gate | FAIL |
| 1% FPR gate | FAIL |

The low ROC-AUC indicates a substantial cross-domain ranking/distribution shift, not merely a threshold-calibration problem.

## Attack-type recall / benign FPR

| ToN-IoT type | Support | Result |
|---|---:|---:|
| backdoor | 20,000 | recall 0.025% |
| ddos | 20,000 | recall 0.035% |
| dos | 20,000 | recall 0.015% |
| injection | 20,000 | recall 0.060% |
| mitm | 1,043 | recall 2.589% |
| password | 20,000 | recall 3.145% |
| ransomware | 20,000 | recall 0.000% |
| scanning | 20,000 | recall 0.030% |
| xss | 20,000 | recall 0.010% |
| normal | 50,000 | FPR 37.888% |

## Engineering implication

This result rejects the claim that the current portable binary detector generalizes universally across unrelated network domains. The product should therefore treat domain compatibility as a safety gate: unsupported telemetry distributions should remain in shadow/abstain mode until domain-specific validation is completed.

This result does **not** invalidate the separate V88 UNSW independent-source replication, the state-forecasting experiments, or the live runtime latency benchmark. Those are different evidence scopes and must remain reported separately.
