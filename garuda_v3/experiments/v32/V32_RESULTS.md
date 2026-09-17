# V32 300k-row expanded-support isolation baseline

V32 changed only the IoT-23 per-scenario raw-row cap from 100,000 to 300,000. V29's strict network-only topology/periodicity representation, supervised + benign-novelty model, global policy-only fusion/threshold logic, and split hygiene were reused. Event reporting uses the corrected evaluable clean-onset denominator.

Evidence run: GitHub Actions `35053443584`  
Job: `104658541987`  
Artifact: `garuda-v32-expanded-support-evidence` (`10430345589`)  
Artifact SHA256: `3ca6370ffbd6c7a5543c50ac5db8d5efade40e18720ae640f9335e96f4e38d50`

## Mean results across seeds 42/43/44

| Held-out development behaviour | Reserved-benign FPR | Sequence recall | Evaluable-event recall | Unsupported events | Mean max lead |
|---|---:|---:|---:|---:|---:|
| c&c-heartbeat | 3.8316% | 5.5556% | 33.3333% | 0 | 40 s |
| c&c | 3.7629% | 33.3333% | 100.0000% | 1 | 90 s |
| partofahorizontalportscan | 0.9509% | 0.0000% | 0.0000% | 1 | 0 s |
| **Macro** | **2.8485%** | **12.9630%** | **44.4444%** | — | **43.33 s** |

Development gate: **FAIL**.

- Macro FPR <=2%: fail (2.8485%).
- Macro evaluable-event recall >=80%: fail (44.4444%).
- Every family evaluable-event recall >=70%: fail.
- Positive lead time >=30 s for every family: fail because horizontal scan is not detected.
- Unsupported events are explicitly reported: pass.

## Interpretation

Increasing the row cap materially extends several high-volume capture spans, but it does not solve the forecasting gate. C&C remains the clearest transferable precursor (100% evaluable-event recall, 90 s mean max lead), while heartbeat is seed-unstable and horizontal scan remains undetected. The row-cap expansion therefore is **not the main fix**.

This closes the "more of the same IoT-23 rows" hypothesis as the primary development direction. Subsequent work should prioritize a corpus with many independently timestamped clean onsets and enough pre-attack support, plus cross-capture calibration. V33 identifies such a corpus in the UNSW IoT Attack Traces.

Final validation remains locked.
