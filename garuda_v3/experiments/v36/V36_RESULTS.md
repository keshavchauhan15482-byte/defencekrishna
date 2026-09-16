# V36 UNSW cross-device domain-shift diagnostic

Authoritative run: GitHub Actions `35061918837` (job `104683854970`).
Evidence artifact: `garuda-v36-domain-shift-evidence` (`10432483913`), ZIP SHA256 `6c9b61426a81e282b1aa0071c88a6918d001c6746aaa4cf8512dc29f3a80caff`.

V36 trained **no attack forecaster** and selected **no attack threshold**. It reused V35 clean-history network-only features only to diagnose cross-device domain shift and attack-label overlap.

## Benign domain shift

A fixed logistic domain classifier was asked to distinguish clean benign histories from pooled V35 training devices vs the two V35 test devices.

- Domain ROC-AUC: **0.993885**
- Domain accuracy: **97.675%**
- Diagnostic holdout: **12,000** benign histories
- Pooled per-feature standardized median shift: median **0.0**, mean **0.1006**, p90 **0.2949**, max **1.8599**

The univariate median shifts are mostly small, but the multivariate benign representation identifies held-out devices almost perfectly. This confirms strong device/domain fingerprinting in the V35 feature space.

## Attack-label overlap

- Distinct train-device labels: **45**
- Distinct test-device labels: **30**
- Test labels unseen on train devices: **0**
- Test annotated events: **63**
- Test evaluable clean-onset events: **52**
- Evaluable events with a label unseen on train devices: **0 / 52 (0%)**

Therefore V35's recall collapse is **not explained by an unseen attack-label split**. The dominant diagnosed issue is cross-device representation shift.

## Decision

`strong_domain_shift = true`

`label_shift_material = false`

Next development step: remove channel/device fingerprint by testing pre-frozen scale-free and anonymous temporal-dynamics representations on development devices only. Do not lower the V35 threshold to manufacture recall. The V35 test devices are already inspected development data and cannot be relabeled as fresh final validation after representation changes.
