# V39 invariant temporal LSTM result

Authoritative run: GitHub Actions `35063445836` (job `104688502956`).
Evidence artifact: `garuda-v39-temporal-lstm-evidence` (`10432629334`), ZIP SHA256 `9fcfca3f50366a3c76c00d9c6f06a07e4502a314d90c544067692dcf929b07a2`.

The exact 7x12 fraction-difference temporal representation first passed a benign-only cross-device invariance gate:

- mean benign domain ROC-AUC: **0.56294**
- maximum fold domain ROC-AUC: **0.61432**

So the V39 representation did not reintroduce the strong device fingerprint diagnosed in V36.

## LSTM mean over four whole-device folds x three seeds

- FPR: **9.3169%** — gate <=5% FAIL
- sequence recall: **11.4484%** — gate >=70% FAIL
- precision: **0.19624%**
- F1: **0.32159%**
- PR-AUC: **0.001498**
- evaluable-event recall: **18.5618%** — gate >=80% FAIL
- mean detected-event median max lead: **108.29 s** — lead gate PASS

Same-input flattened HGB baseline:
- FPR **2.7042%**
- sequence recall **3.0678%**
- PR-AUC **0.001602**
- event recall **9.3561%**

The LSTM increased event recall relative to the static baseline but did not improve ranking enough; PR-AUC stayed near rare-event prevalence and seed/domain threshold transfer remained unstable. One fold/seed reached high recall only with an unusable **73.9% FPR**, demonstrating that simply lowering thresholds would manufacture recall rather than solve forecasting.

## Per-fold LSTM means

- fold0: FPR **10.32%**, sequence recall **10.84%**, event recall **25.00%**, 52 evaluable events, lead **141.86 s**
- fold1: FPR **25.28%**, sequence recall **27.43%**, event recall **32.35%**, 34 evaluable events, lead **143.92 s**
- fold2: FPR **1.57%**, sequence recall **7.00%**, event recall **15.94%**, 23 evaluable events, lead **106.24 s**
- fold3: FPR **0.095%**, sequence recall **0.52%**, event recall **0.95%**, 35 evaluable events, lead **41.14 s**

## Conclusion

V36/V37/V39 together isolate the remaining problem: device identity was a real confound and has been largely removed, but the fully attack-free pre-onset histories in this victim/device aggregate dataset contain very weak, non-transferable information about the next externally initiated attack onset. A larger or deeper classifier is not the justified next move.

The next protocol should forecast **attack progression from observable early malicious stages** (for example Reconnaissance/Weaponisation -> Exploitation/later stages) rather than demand prediction of an arbitrary first malicious packet from completely benign victim history. This remains a pre-compromise forecasting task but provides causal network precursors that can actually exist in telemetry. Final claims still require newly reserved external validation.
