# V31 IoT-23 row-cap temporal-support audit

V31 is a support-only audit. No model was trained, no threshold was selected, and no final-validation family was scored.

Evidence run: GitHub Actions `35053193746`  
Artifact: `garuda-v31-rowcap-support-evidence` (`10430165200`)  
Artifact SHA256: `69906293804a41667197b029618dc63db37ba97292e2f19b8a3613853e848838`

## Aggregate 100k vs 300k rows per scenario

| Support measure | 100k cap | 300k cap | Delta |
|---|---:|---:|---:|
| Loaded scenarios | 19 | 19 | 0 |
| Scenarios with >=12 min span | 13 | 16 | +3 |
| Eligible clean-history sequences | 10,291 | 10,332 | +41 (+0.3984%) |
| Clean-history future-positive sequences | 149 | 149 | 0 |
| Heartbeat evaluable onsets / candidates | 1 / 6 | 1 / 6 | 0 / 0 |
| C&C evaluable onsets / candidates | 1 / 3 | 1 / 3 | 0 / 0 |
| Horizontal-scan evaluable onsets / candidates | 2 / 9 | 2 / 9 | 0 / 0 |

The audit's pre-frozen automatic decision is `recommend_expand_next_model_row_cap=true` because three additional high-volume scenarios cross the 12-minute usability boundary. However, the quantities that directly support the three development forecasting targets do **not** increase: future-positive support and all held-out-family clean-onset candidate counts are unchanged. Clean-history support rises only 0.3984%.

## Interpretation

The 100k truncation is real and can make some high-volume scenarios temporally unusable (for example, 3-11 minute spans become longer at 300k), but it is **not the main cause of the current development-family recall/FPR failure**. The extra 200k rows do not add any new clean future-positive sequence or any new clean-onset candidate for heartbeat, C&C, or horizontal scan.

The next experiment therefore uses 300k only as an **isolation baseline** while keeping the V29 model and global policy threshold fixed. If metrics remain materially unchanged, further row-cap expansion should be deprioritized and work should move to cross-scenario representation/calibration and better onset data.

Final validation remains locked.
