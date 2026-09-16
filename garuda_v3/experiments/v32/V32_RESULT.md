# V32 result — 300k expanded-support isolation baseline

Authoritative run: GitHub Actions `35053443584` on the frozen V32 protocol.

V32 changed only the IoT-23 per-scenario row cap from 100k to 300k while preserving V29 strict network-only features, model architecture, global policy-only threshold selection, split hygiene, and V30 evaluable-event accounting.

## Result

- Macro FPR: **2.8485%** — gate <=2% not met.
- Macro sequence recall: **12.9630%**.
- Macro evaluable-event recall: **44.4444%** — gate >=80% not met.
- Mean lead-time summary: **43.33 s**, but the all-family positive-lead gate failed because scan had no detections.
- C&C: **100% evaluable-event recall**, 90 s mean max lead, FPR 3.7629%.
- C&C-heartbeat: **33.33% evaluable-event recall**, 40 s mean max lead, FPR 3.8316%.
- Horizontal port scan: **0% evaluable-event recall**, FPR 0.9509%.
- Unsupported clean-onset events remain explicit: 1 C&C onset and 1 scan onset had no eligible 8-minute clean-history candidate.

Compared with V30's scenario-calibrated experiment, expanded data materially reduced macro FPR (9.83% -> 2.85%) but did not solve precursor ranking/recall. Therefore the next step is a score-margin diagnostic, not another blind architecture/threshold change.

Full Krishna Defence regression on the same V32 head passed (`35053443543`).
