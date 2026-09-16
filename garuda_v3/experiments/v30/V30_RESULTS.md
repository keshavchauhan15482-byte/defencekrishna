# V30 evaluable-event scenario-calibrated development result

V30 corrected the event denominator exposed by V29: onsets with zero eligible clean 8-minute history are reported as coverage gaps instead of model false negatives. The model/fusion family remained fixed and thresholds were selected only from policy data.

Evidence run: GitHub Actions `35052512491`  
Artifact: `garuda-v30-evaluable-calibrated-evidence` (`10430055171`)  
Artifact SHA256: `6f1404861eaa27f54cbf5176af8a86f1a0d5ee832008404ce1bd553a1bfc7e39`

## Mean results across seeds 42/43/44

| Held-out development behaviour | Reserved-benign FPR | Sequence recall | Evaluable-event recall | Unsupported events | Mean max detected lead |
|---|---:|---:|---:|---:|---:|
| c&c-heartbeat | 14.9485% | 5.5556% | 33.3333% | 0 | 30 s |
| c&c | 2.7835% | 33.3333% | 100.0000% | 1 | 90 s |
| partofahorizontalportscan | 11.7626% | 11.1111% | 33.3333% | 1 | 120 s |
| **Macro** | **9.8315%** | **16.6667%** | **55.5556%** | — | **80 s** |

Development gate: **FAIL**.

- Macro FPR <=2%: fail (9.8315%).
- Macro evaluable-event recall >=80%: fail (55.5556%).
- Every family evaluable-event recall >=70%: fail.
- Positive lead time >=30 s for every family: pass.
- Unsupported events are explicitly reported: pass.

## Interpretation

The corrected denominator confirms a real clean-history precursor signal for the evaluable C&C onset: all three seeds detect it with a 90-second maximum lead. Heartbeat and horizontal-scan transfer remain unstable. Scenario-specific policy thresholds do **not** solve false-positive transfer; they worsen the aggregate reserved-benign FPR relative to V29.

A separate data-support problem remains visible: V29/V30 intentionally cap each IoT-23 scenario at 100,000 raw rows. Several high-volume captures therefore cover only a few minutes, which can remove the 8-minute benign prehistory and the 4-minute future context required by the protocol. The next experiment is a support-only row-cap audit before changing the model again.

Final-validation families remain locked and are not scored by this development result.
