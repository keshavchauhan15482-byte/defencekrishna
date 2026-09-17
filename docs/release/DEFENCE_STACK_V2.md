# Defence Stack V2 — Local Contract Evidence

This note documents the deterministic local/module validation contract for the Arjuna → Krishna → Sudarshana defensive loop. It is **not** production zero-day evidence and does not change Garuda forecasting weights.

## Routing contract

- Known/static threats are handled by the Arjuna fast path.
- Unseen structural signals are routed to Krishna for study; this wording means unseen-to-system/unknown structure, not a verified real-world zero-day.
- Sudarshana remains a scoped containment layer under the existing confirmed-escape/breach gate.
- Only independently validated, sufficiently specific mutation signatures may be promoted into Arjuna mutation memory.

## Mutation budget

Krishna mutation generation is adaptive rather than a fixed number per attack. A single incident can extract multiple root tokens, and each root can generate a different number of candidate variants.

The V2 hardening layer bounds the validation/persistence workload to:

- **96 mutation candidates per extracted root token**
- **256 mutation candidates per incident**

Candidates beyond the budget are withheld from validation/promotion. The runtime reports generated-before-budget, evaluated candidates, withheld candidates, independently validated candidates, validation coverage, and Arjuna promotion reuse.

These budgets prevent an unusually complex payload from causing unbounded mutation-study work while preserving the existing adaptive generator.

## Release gates

The deterministic local effectiveness test requires:

- benign danger rate ≤ 10% on the small curated sanity set,
- known-attack block rate ≥ 80%,
- all five curated novel structural cases to route to Krishna,
- mutation budgets not to be exceeded,
- at least one independently validated/promotable mutation,
- 100% Arjuna reuse for mutations that pass the promotion gate.

The measured values from the final CI run should be treated as local regression evidence only. Cross-dataset Garuda evidence remains documented separately in the V48/V52 release evidence files.
