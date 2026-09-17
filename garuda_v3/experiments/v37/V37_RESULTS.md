# V37 invariant representation result

Authoritative run: GitHub Actions `35062307986` (job `104685013056`).
Evidence artifact: `garuda-v37-invariant-representation-evidence` (`10432474720`), ZIP SHA256 `f4b6ed708c955e5bbdc2bd15bb7c84efaf5602b7e753f145c3187c490d97e730`.

V37 trained no attack forecaster and used no positive attack outcome to select a feature view. It used clean benign histories from the eight development devices only; the two V35 test devices were excluded from selection.

## Benign device-domain separability

- V35 full 231-D view: mean domain ROC-AUC **0.9860**
- Derivative channels, 99-D: **0.6768**
- Fraction derivatives, 36-D: **0.5353**
- Anonymous dynamics, 56-D: **0.9437**
- Anonymous derivatives, 42-D: **0.8931**
- Anonymous fraction derivatives, 21-D: **0.8534**

The frozen selection rule chose **`fraction_derivatives` (36-D)**. It was the unique view within 0.01 of the best mean domain ROC-AUC and passed the preferred invariance target (<=0.70). Its maximum fold domain ROC-AUC was **0.5650**, with mean domain accuracy **56.02%**, close to chance.

This is a major structural improvement over the V35 representation: removing stationary/absolute channel state and retaining only temporal derivatives of scale-free fraction/concentration channels largely removes device identity from clean benign histories.

Next step: evaluate `fraction_derivatives` in grouped cross-device attack-onset forecasting on development devices only. The old V35 test devices remain development data and cannot be presented as fresh final validation after V35/V36 inspection.
