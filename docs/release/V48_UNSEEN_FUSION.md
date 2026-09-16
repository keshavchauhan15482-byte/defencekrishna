# V48 — Frozen unseen-family alert fusion

V47 showed that Garuda's temporal world model could transfer state dynamics to some held-out families while a conventional known-attack classifier often transferred with higher recall but too many false positives. V48 combines those complementary signals while protecting the unseen-family claim from test-guided tuning.

## Development versus reserve families

The five families whose V47 metrics were already published are permanently development-only for V48:

- Tampering
- Lateral Movement
- Weaponization
- Exfiltration
- Reconnaissance

Before any family-disjoint split is built, family metadata is canonicalized by case-folding, converting underscores to spaces and collapsing repeated whitespace. Dataset spellings such as `Lateral _movement` and `Lateral Movement` therefore represent the same family identity.

Support-qualified canonical non-V47 families are selected as the reserve set using support counts only. Every sequence touching a reserve family, plus a full history+horizon overlap embargo around those episodes, is removed from V48 score-development training, calibration, policy blocks and fusion-selection metrics. The score configuration is serialized and SHA-256 hashed before reserve metrics are computed.

## Five inference-time signals

The candidate fusion can use:

1. known-attack transfer probability from observed history;
2. predicted future-state novelty;
3. predicted transition/delta novelty;
4. world-model transition energy relative to persistence;
5. current-history state novelty.

Every signal is converted to benign-tail evidence using benign calibration traffic only. The alert threshold comes from benign policy traffic only.

## Authoritative frozen configuration

On the post-canonicalization run, V48 selected this configuration using development families only:

- 75% known-attack transfer;
- 25% world-model transition energy;
- policy budget 0.25%;
- config SHA-256 `4b1a25da56bfd7b7e07e9ae542cf9993485be8437924d479536415508889ad6a`.

The authoritative reserve families were `exploitation` and `c&c`. Their metrics were not used to choose the weights, components or policy budget.

## Release gate and measured result

A reserve family passes only if every seed 42/43/44 satisfies:

- validation state forecasting beats persistence;
- benign test FPR <=1%;
- unseen-family recall >=80%.

Authoritative run `35107130823` produced:

- **Exploitation:** 91.88% mean recall, 0.390% mean FPR, 97.08% mean precision, 94.41% mean F1; all three seeds pass state and unseen gates.
- **Command & Control:** 87.63% mean recall, 0.366% mean FPR, 97.02% mean precision, 92.08% mean F1; all three seeds pass state and unseen gates.

`all_reserve_unseen_gates_passed = true`.

See `V48_RESULTS.md` for the evidence record and the retained ToN-IoT support audit.

## Evidence hygiene note

An earlier exploratory run `35105863772` is invalid for unseen-family evidence because the dataset spelling `Lateral _movement` was temporarily treated as distinct from the already-exposed V47 development label `Lateral Movement`. Canonicalization and a regression test were added before the authoritative run. Only the post-fix reserve result may be cited.

## Claim boundary

V48 supports the controlled statement that a frozen Garuda fusion generalized to two public-dataset attack families excluded from V48 model fitting, calibration, policy selection and score development while meeting the <=1% FPR / >=80% recall gate across three seeds.

It does not prove a truly undisclosed production zero-day, verified warning before successful compromise, validated MITRE progression timing, successful compromise prevention, or autonomous enterprise-containment readiness. Those stronger claims require newly reserved independent campaigns with verified attack/compromise timelines and clean pre-attack histories.
