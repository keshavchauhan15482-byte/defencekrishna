# V48 — Frozen-score reserved unseen-family evaluation

V48 follows directly from the negative V47 result. V47 showed that Garuda's state forecast can transfer to several held-out attack families, while the original benign predicted-trajectory anomaly score misses too many unseen attacks. The known-attack logistic baseline transfers strongly to some unseen families but exceeds the 1% FPR target.

V48 asks a narrower question: **can a warning score be selected on already-exposed pseudo-unseen families, frozen, and then transfer to attack families whose model metrics were not used during score design?**

## Frozen development vs reserve families

Development pseudo-unseen folds are the five families already exposed by V47:

- Tampering
- Lateral Movement
- Weaponization
- Exfiltration
- Reconnaissance

Reserve families are frozen before V48 scoring:

- **C&C**
- **Exploitation**

V47 reported their support counts but did not run/publish model metrics for these two families. RDoS remains excluded because support is too small for the target gate.

No C&C or Exploitation positive metric participates in score selection.

## Network-only evidence

The same strict X-IIoTID network-only allow-list is used. Process/resource telemetry, OSSEC/alert fields, login fields, class/attack labels and IP identifiers as learned numeric inputs remain excluded. IP can only group source timelines.

## Candidate warning signals

For every pseudo-unseen development family, the family is removed from training, state validation, benign calibration and policy threshold fitting.

The LSTM world model produces a four-step predicted future state. Candidate runtime scores are built only from information available at the forecast cutoff:

### Pure world-model candidates

- `world_future`: benign-tail surprise of the predicted future trajectory.
- `world_delta`: benign-tail surprise of the model's predicted change relative to persistence/current state.
- `world_delta_future`: equal mixture of future-state and predicted-change surprise.

### Transferable known-attack signal

A logistic history model is trained on benign plus the remaining known attack families. Its probability is converted to a benign empirical tail-surprise score. The held-out family has zero supervised exposure.

### Hybrid candidates

Fixed combinations of logistic surprise and world-model change/future surprise are compared, including 75/25, 50/50, 25/75 weighted mixtures, a three-signal mixture, an AND-like minimum and an OR-like maximum.

No candidate weights are optimized continuously and no reserve-family metrics are used to choose a candidate.

## Candidate selection rule

For pure-world and hybrid groups separately, V48 uses one predeclared lexicographic rule across the five development pseudo-unseen families:

1. maximize number of families satisfying both FPR <=1% and recall >=80%;
2. maximize number of families satisfying FPR <=1%;
3. maximize recall among FPR-budget families;
4. maximize overall recall;
5. prefer lower overall FPR;
6. deterministic candidate-name tie break.

This produces one frozen pure-world score and one frozen hybrid score.

## Reserve evaluation

Only after score selection is complete, C&C and Exploitation are evaluated with seeds 42/43/44. For each reserve family, the family remains excluded from model development. The reserve report compares:

- frozen pure-world score;
- frozen hybrid score;
- logistic-only baseline;
- state forecast MSE vs persistence.

The 1% alert threshold is still fit only on family-free benign policy samples.

## Claims boundary

Even a successful V48 result supports only:

> a frozen warning rule transferred to public-dataset attack families excluded from score/model development.

It is **not** proof of a real undisclosed zero-day, verified pre-compromise lead time, successful prevention, MITRE progression accuracy or production readiness. Those require newly reserved real campaigns with independently verified incident timelines/outcomes.
