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

Before any family-disjoint split is built, family metadata is canonicalized by case-folding, converting underscores to spaces and collapsing repeated whitespace. This makes dataset spellings such as `Lateral _movement` and `Lateral Movement` the same family identity.

Before any V48 scorer/model tuning begins, support-qualified canonical non-V47 families are selected as the **reserve set using support counts only**. Every sequence touching a reserve family, plus a full history+horizon overlap embargo around those episodes, is removed from V48 score-development training, calibration, policy blocks and fusion-selection metrics. This prevents a reserve family from leaking into the known-attack transfer model, world-model fitting or score-selection evidence.

The score configuration is then serialized with a SHA-256 hash. Only after that frozen configuration exists are reserve-family model metrics evaluated. Reserve metrics cannot alter the feature set, component definitions, weights, budget or thresholding rule.

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

## Evidence hygiene note

An earlier exploratory V48 run exposed a label-alias problem: the dataset spelling `Lateral _movement` was treated as distinct from the V47 development label `Lateral Movement`, allowing the same semantic family to enter the reserve list. That exploratory run is **invalid for unseen-family evidence**. Family canonicalization and a regression test were added before the authoritative rerun. Only post-fix results may be cited.

## Claim boundary

A strong reserve result would support:

> A fixed Garuda alert fusion, selected without reserve-family development exposure, transfers to a public-dataset attack family excluded from score development.

It would not prove:

- detection of an undisclosed production zero-day;
- verified warning before successful compromise;
- prevention of compromise;
- validated MITRE progression timing;
- autonomous enterprise containment readiness.

Those stronger claims still require newly reserved campaigns with independently verified attack/compromise timelines and clean pre-attack histories.
