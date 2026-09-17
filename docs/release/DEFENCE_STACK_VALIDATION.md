# Krishna Defence — Arjuna / Krishna / Sudarshana validation

**Validation date:** 2026-09-17  
**Validated code head:** `fc066ea0d516bc1e9b4662ec7b331dfc212b9b8f`  
**GitHub Actions run:** `35184264843`  
**Scope:** deterministic local/owned-lab defensive validation only

This report records what the executable defence stack actually demonstrated after aligning the implementation with the intended Krishna Defence routing model. It is not a production certification and it is not evidence that a real-world zero-day or successful compromise was prevented.

## Intended routing contract

1. **Garuda AI** provides forecasting/risk evidence through the existing model path.
2. **Arjuna** owns reviewed known-threat memory and the fast block path.
3. **Krishna** handles unknown/high-risk structures, studies them, generates related mutations and promotes only validated reusable knowledge.
4. **Sudarshana** remains on standby when Arjuna or Krishna already contained the event. Scoped IP lockdown requires explicit evidence that the unknown threat escaped the first defensive boundary.
5. Recovery from a Sudarshana lockdown remains fail-closed until Krishna study evidence satisfies the configured recovery gate.

## Measured local effectiveness

The deterministic module benchmark used documentation-range IP addresses and no external target traffic.

| Local contract | Observed result |
|---|---:|
| Benign examples classified `danger` | **0 / 10** |
| Known attack examples classified `danger` | **10 / 10** |
| Synthetic novel-structure examples classified `danger` | **5 / 5** |
| Synthetic novel-structure examples routed to Krishna | **5 / 5** |
| Mutation candidates generated in this CI run | **132** |
| Mutations independently re-detected and eligible for promotion | **114** |
| Mutation validation coverage in this CI run | **86.36%** |
| Promotion-eligible validated mutations reusable by Arjuna | **114 / 114** |

The three mutation seed families in this run were SQL injection, XSS and SSRF. Their generated/validated counts were:

- SQL injection: 80 candidates, 70 validated.
- XSS: 38 candidates, 32 validated.
- SSRF: 14 candidates, 12 validated.

Mutation generation can vary between runs; the counts above belong specifically to Actions run `35184264843`. Generated candidates are **not** trusted simply because Krishna synthesized them. Promotion requires independent danger re-detection using a fresh detector with learned memory disabled plus the Arjuna reusable-signature gate.

## Defence-loop contract checks

The hardened defence contract passed **12 / 12** local checks, including:

- low-confidence incidents cannot poison Arjuna memory;
- Krishna independently validates a root incident before learning it;
- generated-but-unvalidated mutations cannot become Arjuna block decisions;
- Arjuna recognizes independently validated related mutations;
- known/static threats do not unnecessarily trigger Sudarshana;
- unknown threats contained by Krishna do not trigger Sudarshana without escape evidence;
- confirmed unknown escape evidence can activate scoped Sudarshana containment;
- unresolved confirmed escapes remain fail-closed;
- only the confirmed offender scope is locked;
- validated Krishna study allows time-bound recovery while the ledger remains intact.

A separate structural regression passed **2 / 2** checks: JSON-escaped bracket-notation `constructor/prototype` structure was routed as dangerous/unknown, while benign prose mentioning the words `constructor` and `prototype` remained safe.

## Broader regression evidence

The same full-integration run also passed:

- **148** Garuda Python tests (`31` optional research-dependency tests skipped);
- **7** NTRO data-integrity tests;
- proxy exposure checks;
- **15 / 15** legacy V11 control checks;
- **12 / 12** loopback HTTP enforcement checks;
- **10 / 10** V15 system-integration checks;
- localhost launcher health smoke test.

The loopback HTTP checks demonstrate scoped policy enforcement behavior such as keeping an unrelated client available, rejecting stale/invalid revocation, respecting TTL expiry and preventing a known malicious request from reaching the upstream application.

## What was fixed

### Arjuna

Validated mutation memory is now part of the actual known-threat fast path. Bloom membership alone is never sufficient authority; exact/canonical matching is restricted to independently validated mutation records.

### Krishna

Low-confidence learning is rejected. Ordinary known/static danger already handled by Arjuna is not redundantly promoted through Krishna. Synthetic variants require independent validation before they can become trusted known-threat memory.

### Sudarshana

Sudarshana no longer treats every unknown alert as proof of a breach. If Krishna already contained the unknown/high-risk event, Sudarshana stays in `STANDBY_KRISHNA_CONTAINED`. Scoped lockdown requires explicit `confirmed` escape/breach evidence with a named source. Once engaged, incomplete Krishna study remains fail-closed.

### Structural evidence normalization

JSON escaping previously hid one bracket-notation prototype-chain structure from the structural heuristic. The hardening layer now normalizes only quote escaping for defensive structural inspection; it does not rewrite the request bytes forwarded to the protected application.

## Claim boundary

These results support a **local deterministic defence-contract claim**, not universal detection statistics.

Do **not** interpret:

- `0 / 10` benign danger as a measured production false-positive rate;
- `10 / 10` known cases as 100% detection of all known attacks;
- `5 / 5` synthetic novel structures as proof of real-world zero-day detection;
- local scoped containment as proof of successful-compromise prevention;
- mutation validation coverage as cross-dataset generalisation.

This run did **not** test Garuda-triggered attacker-IP attribution, a real protected-backend compromise, external attack traffic or enterprise deployment. The current Python Garuda unknown-forecast path retains its existing fail-closed/shadow authority boundary.

For forecasting/generalisation evidence, use `RELEASE_EVIDENCE.md`, `docs/release/V48_RESULTS.md` and `docs/release/V52_CICAPT_TIMELINE.md` separately.
