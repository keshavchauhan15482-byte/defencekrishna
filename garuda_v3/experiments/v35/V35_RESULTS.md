# V35 UNSW cross-device clean-onset forecasting result

Authoritative completed run: GitHub Actions `35054809164` (job `104662625469`).
Evidence artifact: `garuda-v35-unsw-cross-device-evidence` (`10429949721`), ZIP SHA256 `317eee795091c32725bf11aa2d8f27050e05eee8436b1edd3630cde328b94967`.

V35 used the pre-frozen whole-device split, strict network-only device-agnostic features, attack-free 8-minute histories, a 4-minute onset horizon, calibration on the calibration device only, and a policy-device-only 5% benign-FPR threshold. Test devices were absent from train/calibration/policy.

## Test support

- Test samples: **110,273**
- Benign test samples: **110,094**
- Positive future-onset sequences: **179**
- Annotated test events: **63**
- Evaluable clean-onset events: **52**
- Unsupported events: **11**

## Primary HGB mean over seeds 42/43/44

- FPR: **1.08695%** — gate <=5% PASS
- Sequence recall: **2.04842%** — gate >=70% FAIL
- Precision: **0.22042%**
- F1: **0.39778%**
- PR-AUC: **0.002277**
- Evaluable-event recall: **3.84615%** — gate >=80% FAIL
- Evaluable-event support: **52** — gate >=20 PASS
- Mean of per-seed detected-event median max lead: **140.12 s** — lead gate PASS, but only among the very small detected subset

Seed event recall was 5.77%, 5.77%, and 0%. The logistic baseline had 0% sequence and event recall at ~0.253% FPR.

## Interpretation

V35 is an honest cross-device generalization failure, not a support shortage. FPR is controlled and the held-out test contains substantial clean-onset support, but ranking/recall collapses across devices. The very low PR-AUC is close to the rare positive prevalence, which points to weak device-invariant precursor separability rather than a threshold-only problem.

A few events do show long precursor lead time (~200 s in seeds 42/43), but the signal is too rare and unstable to support a forecasting claim.

Because V35 test results have now informed development, these two devices are no longer an untouched final-validation set for any representation chosen afterward. Future final claims require a newly reserved external dataset/campaign.
