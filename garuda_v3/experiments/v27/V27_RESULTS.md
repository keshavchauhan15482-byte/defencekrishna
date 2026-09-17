# V27 clean-history unseen precursor evidence

V27 corrected a major evaluation shortcut by allowing only attack-free 8-minute histories in train, calibration, policy and held-out evaluation. The held-out family and all blocks exposing it were absent from train/calibration/policy.

Evidence run: GitHub Actions `35049532109`, job `104646682220`.
Evidence artifact: `garuda-v27-clean-precursor-evidence`, artifact id `10428666061`, artifact SHA-256 `e3b7c0607d0c3847372b83943c3fddd2fe177a407836bebf960428f43e7fde93`.

## Frozen development result

| Held-out behaviour | Mean test FPR | Sequence recall | Event recall | Max lead mean |
|---|---:|---:|---:|---:|
| c&c-heartbeat | 4.8797% | 94.44% | 100% | 180 s |
| c&c | 1.0309% | 0% | 0% | 0 s |
| partofahorizontalportscan | 0.7924% | 0% | 0% | 0 s |
| **Macro** | **2.2343%** | **31.48%** | **33.33%** | **60 s** |

Development gate: **FAIL**.

The result is scientifically useful rather than deployable: c&c-heartbeat has a repeatable clean-history precursor under the current representation, while generic c&c and horizontal scan do not transfer from the single 4-minute binary future-risk target. This motivates the pre-frozen V28 multi-horizon hazard experiment. Final-validation families remain locked.
