# V48 — Frozen unseen-family alert fusion

V47 proved that the current problem is not simply model size. The temporal world model often transferred state dynamics to a held-out family, but its single benign-future anomaly score had low recall. A conventional known-attack logistic history model often had much higher recall on the same held-out families, but exceeded the requested 1% false-positive budget.

V48 combines those complementary signals while protecting the unseen-family claim from test-guided tuning.

## Development versus reserve families

The five families whose V47 metrics were already published are permanently treated as **development pseudo-unseen families** for V48:

- Tampering
- Lateral Movement
- Weaponization
- Exfiltration
- Reconnaissance

V48 is allowed to choose fusion weights and a conservative benign policy budget using those exposed outcomes.

After the score configuration is chosen, it is serialized with a SHA-256 hash. Only then are support-qualified families that were not used in V47 score development selected as **reserve families**, using positive/negative support counts only. Reserve metrics do not alter the feature set, component definitions, weights, budget or thresholding rule.

This gives a cleaner secondary holdout for alert-score development. It still does not convert a public dataset family into a real undisclosed zero-day.

## Five inference-time signals

All signals use network telemetry and model outputs available before the future ground truth is known:

1. **Known-attack transfer** — history-only logistic probability trained without the held-out family.
2. **Future-state novelty** — robust distance of the world model's predicted future trajectory from benign predicted futures.
3. **Predicted-delta novelty** — robust distance of the predicted transition vector from benign predicted transitions.
4. **Transition energy** — magnitude of the model's predicted departure from persistence.
5. **History-state novelty** — robust distance of the current network state from benign current states.

Every raw signal is converted to benign-tail evidence using only benign calibration traffic. The fusion is a non-negative weighted sum. The final alert threshold is chosen from benign policy traffic only.

## Fusion selection

V48 searches a small, predeclared candidate set: individual components, logistic/world pairs at 75/25, 50/50 and 25/75, several three-way combinations, a world-transition-only combination and all-equal fusion.

It also evaluates conservative policy budgets of 0.1%, 0.25%, 0.5% and 1.0% on the exposed V47 development folds. Selection is deterministic and lexicographic:

1. number of state-valid folds satisfying FPR <=1% and recall >=80%;
2. recall accumulated across state-valid safe folds;
3. number of safe folds;
4. mean safe-fold recall;
5. lower worst observed FPR;
6. lower policy budget.

The winning configuration is frozen before reserve evaluation.

## Release gate

For a reserve family to pass the V48 unseen-family gate on all three seeds:

- its state model must beat persistence on family-free validation;
- benign test FPR must be <=1%;
- unseen-family recall must be >=80%.

Seeds 42, 43 and 44 are all reported; there is no best-seed promotion.

## Claim boundary

A strong reserve result would support:

> A fixed Garuda alert fusion, selected without the reserve family, transfers to a public-dataset attack family excluded from score development.

It would not prove:

- detection of an undisclosed production zero-day;
- verified warning before successful compromise;
- prevention of compromise;
- validated MITRE progression timing;
- autonomous enterprise containment readiness.

Those stronger claims still require newly reserved campaigns with independently verified attack/compromise timelines and clean pre-attack histories.
