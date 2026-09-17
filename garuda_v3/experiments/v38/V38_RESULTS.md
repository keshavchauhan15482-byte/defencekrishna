# V38 invariant cross-device clean-onset forecasting result

Authoritative run: GitHub Actions `35062924174` (job `104686880658`).
Evidence artifact: `garuda-v38-invariant-cross-device-evidence` (`10432299556`), ZIP SHA256 `417f13b0795b87861d86f8e605a758d19fd89a61176274c32311e3139afd616c`.

V38 used the 36-D `fraction_derivatives` representation selected in V37 using benign device-invariance only. The two previously inspected V35 test devices were excluded completely. Four whole-device development folds, three seeds each, used disjoint train/calibration/policy/test devices.

## Mean over 12 fold-seed runs

- Test FPR: **9.6084%** — gate <=5% FAIL
- Sequence recall: **12.1572%** — gate >=70% FAIL
- Precision: **0.13699%**
- F1: **0.26766%**
- PR-AUC: **0.001531**
- Evaluable-event recall: **22.8973%** — gate >=80% FAIL
- Mean detected-event median max lead: **127.45 s** — lead gate PASS
- Minimum per-fold evaluable support: **23** — support gate PASS

## Per-fold mean

- fold0: FPR **29.6818%**, sequence recall **33.33%**, event recall **55.13%**, 52 evaluable events, mean median max lead **195.92 s**
- fold1: FPR **5.2190%**, sequence recall **7.67%**, event recall **19.61%**, 34 evaluable events, lead **177.31 s**
- fold2: FPR **2.1311%**, sequence recall **6.58%**, event recall **13.04%**, 23 evaluable events, lead **89.88 s**
- fold3: FPR **1.4018%**, sequence recall **1.04%**, event recall **3.81%**, 35 evaluable events, lead **46.68 s**

## Interpretation

V37 successfully removed most device identity from benign feature space, but V38 shows that this alone does not create transferable attack-onset ranking. PR-AUC remains close to rare-event prevalence and recall is poor in three of four folds. Fold0 also shows severe seed/threshold transfer instability: individual test FPR ranged from about 5.3% to 50.3% despite policy-device FPR control.

The next development step should preserve the V37 device-invariant channel policy while exposing the full ordered 8-minute trajectory to a temporal model (rather than compressing it into a static HGB summary). Threshold changes alone are not justified by these results. Any future representation/model selected after V38 still requires new external final validation for a final forecasting claim.
