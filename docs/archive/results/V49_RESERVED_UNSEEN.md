# V49 — Frozen-score reserved unseen-family evaluation

V49 preserves the already merged V48 ToN-IoT support audit and adds a separate X-IIoTID reserve experiment. It follows from V47, where state forecasts transferred to several held-out families but the original world-only warning score had poor recall.

## Development vs reserve families

Development pseudo-unseen folds are the five families already exposed by V47:

- Tampering
- Lateral Movement
- Weaponization
- Exfiltration
- Reconnaissance

Reserve families frozen before this score study:

- **C&C**
- **Exploitation**

V47 exposed their support counts but did not publish model metrics for them. No reserve-family positive metric participates in score selection.

## Runtime evidence

V49 uses the same strict X-IIoTID network-only allow-list as V47. Process/resource telemetry, OSSEC/alert fields, login fields, class labels and IP identifiers as learned numeric inputs remain excluded.

## Candidate scores

### Pure world-model candidates

- `world_future`: benign-tail surprise of the predicted future trajectory.
- `world_delta`: benign-tail surprise of predicted change relative to persistence/current state.
- `world_delta_future`: equal mixture of future-state and predicted-change surprise.

### Hybrid candidates

A known-attack logistic history model is trained without the held-out family. Its score and world-model scores are converted to benign empirical tail-surprise values, then combined using a small predeclared set of fixed rules/weights.

## Frozen selection rule

For pure-world and hybrid candidate groups separately, V49 uses the five exposed development families and this fixed lexicographic rule:

1. maximize number of families satisfying FPR <=1% and recall >=80%;
2. maximize number satisfying FPR <=1%;
3. maximize recall among FPR-budget families;
4. maximize overall recall;
5. prefer lower overall FPR;
6. deterministic name tie-break.

The selected scores are frozen before C&C/Exploitation evaluation.

## Reserve evaluation

C&C and Exploitation are evaluated with seeds 42/43/44 using:

- frozen pure-world candidate;
- frozen hybrid candidate;
- logistic-only baseline;
- state MSE vs persistence.

The held-out family is absent from state training, risk training, benign calibration and policy threshold fitting. Policy thresholds are benign-only.

## Claim boundary

This is a controlled public-dataset family-disjoint simulation. It is not proof of a real undisclosed production zero-day, verified pre-compromise lead time, successful prevention, or MITRE progression accuracy. C&C and Exploitation become exposed after this run and cannot be reused as a fresh final holdout after tuning.
