# V47 zero-day / unseen-attack claim boundary

Garuda's target capability is **generalisation beyond attack families used during development**. V47 measures that capability with a strict family-disjoint public-dataset protocol.

Terminology for SIH presentation:

- **Allowed now:** `unseen-family attack forecasting`, `open-set attack-family simulation`, `held-out-family generalisation`, `zero-supervised-exposure to the held-out family`.
- **Allowed only if the V47 gate passes:** `Garuda detected/forecast an attack family excluded from model development in our controlled benchmark`.
- **Not allowed from V47 alone:** `real zero-day detected`, `unknown exploit detected in production`, `verified zero-day prevention`, or `pre-compromise warning`.

A real zero-day is unknown at model-development and evaluation-design time. X-IIoTID held-out families are known to the dataset publisher and are revealed to the evaluator after inference; therefore V47 is a controlled proxy for novelty/generalisation, not proof of a real undisclosed zero-day.

## V47 unseen-family release gate

A held-out family can be called successfully generalised only when, on the frozen family-disjoint test:

1. the held-out family is absent from training/calibration/policy data;
2. test benign support is at least 50 sequences;
3. held-out-family positive support is at least 20 sequences;
4. benign false-positive rate is <= 1%;
5. held-out-family recall is >= 80%;
6. all reported seeds pass rather than only the best seed;
7. no threshold/feature/model selection used the held-out-family outcomes.

Separately, the world-model state checkpoint must beat persistence on development validation. If it does not, V47 must report `state_model_not_promoted` rather than hiding the failure.

## Stronger evidence still needed

To progress from unseen-family simulation to a defensible real-world zero-day claim, reserve new attack campaigns before inspection, keep exploit/family identity hidden from model development, record successful compromise outcomes independently, preserve clean pre-attack history, and evaluate once on the untouched campaign. Only that stronger experiment can support real pre-compromise novelty claims.
