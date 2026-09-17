# Defence Stack V2 — Local Contract Evidence

This note documents the deterministic local/module validation contract for the current Arjuna → Krishna → Sudarshana defensive loop. It is **not** production zero-day evidence and does not change Garuda forecasting weights.

## Routing contract

- Known/static threats are handled by the Arjuna fast path.
- Unknown/unseen structural signals are routed to Krishna for study; this means unseen-to-system structure, not a verified real-world zero-day.
- Sudarshana retains the current-main confirmed-escape/breach gate before scoped lockdown.
- Only independently validated, sufficiently specific mutation signatures may be promoted into Arjuna mutation memory.

## Mutation budget

Krishna mutation generation is adaptive rather than a fixed number per attack. A unique incident can extract multiple root tokens, and each root can generate a different number of candidate variants.

The current effective runtime bounds mutation generation to:

- **48 candidates per extracted root token**
- **128 candidates per incident**

The runtime reports generated-before-budget, evaluated candidates, withheld candidates, independently validated candidates, validation coverage, and Arjuna promotion reuse. Candidates beyond the budget are not emitted during that learning transaction.

## Arjuna memory separation

Current V5 runtime keeps reviewed known-attack roots and independently validated mutations as separate exact stores. Each store has its own fixed **8192-bit / 1024-byte Bloom prefilter**. Bloom provides a bounded fast membership hint only; exact-store confirmation remains mandatory before Arjuna treats a pattern as known.

The exact/audit stores are intentionally not limited to 1024 bytes. They retain the evidence needed to confirm Bloom matches and preserve mutation-to-root lineage.

## Local release gates

The deterministic effectiveness test requires:

- benign danger rate ≤ 10% on the small curated sanity set,
- known-attack block rate ≥ 80%,
- all five curated novel structural cases to route to Krishna,
- mutation budgets not to be exceeded,
- at least one independently validated/promotable mutation,
- 100% Arjuna reuse for mutations that pass the promotion gate,
- both dedicated Bloom filters to remain exactly 1024 bytes under large synthetic store fixtures.

Measured values from CI are local regression evidence only. Cross-dataset Garuda evidence remains documented separately in the V48/V52 release evidence files.
