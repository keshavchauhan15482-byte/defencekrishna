# V53 — Offline multi-family unknown-attack early-warning stress test

V53 is a non-operational red-team benchmark. It does **not** generate, transmit, or execute attack traffic. It replays public X-IIoTID records offline and asks whether the already-frozen Garuda alert fires before the first future minute containing a selected dangerous attack family.

## Stress families

The requested group holdout is fixed by attack relevance rather than V53 model performance:

- weaponization
- exploitation
- lateral movement
- command & control (`c&c`)
- exfiltration
- ransomware / crypto-ransomware when represented by the dataset family hierarchy
- ransom denial of service (`rdos`)

Missing dataset spellings are reported rather than silently substituted.

## Zero-supervised-exposure protocol

All selected dangerous families are withheld **together** from the V53 model run. Any sequence whose observed history or four-minute future touches a held-out family is excluded from training, state validation, benign calibration and policy fitting, with a full history+horizon overlap embargo around held-out episodes.

Family names are split/evaluation metadata only and never model inputs. Runtime evidence remains restricted to the V47/V48 network-only feature allow-list.

V53 reuses the published V48 alert fusion without tuning on V53 outcomes:

- 75% `known_attack_transfer`
- 25% `transition_energy`
- 0% other V48 components
- benign policy budget: 0.25%
- V48 frozen config reference: `4b1a25da56bfd7b7e07e9ae542cf9993485be8437924d479536415508889ad6a`
- seeds: 42, 43, 44
- observed history: 8 minutes
- forecast horizon: 4 minutes
- reference gate: state model beats persistence, FPR <=1%, recall >=80%

Because several family identities have appeared in prior project experiments, V53 is a **zero-supervised-exposure stress test for this specific V53 model run**, not a fresh project-wide release holdout and not proof of a real undisclosed zero-day.

## Early-warning / lead-time definition

V53 reports ordinary all-episode recall/FPR separately from the stricter event-level early-warning result.

A family-specific clean-onset event is eligible only when:

1. the complete observed history is attack-free;
2. the target family is absent from observed history;
3. the target family appears within the next four minutes; and
4. the target family is present in the **first attack-bearing future minute**.

Rule 4 prevents an alert caused by an earlier different attack from being incorrectly credited as lead time for a later ransomware, C&C, exploitation, or other target-family onset.

For each source/onset event, V53 records the earliest alerting forecast cutoff and therefore lead time of 1, 2, 3, or 4 minutes. It reports event support, warning hits, event recall, mean/median/min/max lead time and hit counts by lead horizon. A separate strict chronological-tail report is produced where support exists.

Lead time means **warning before dataset attack-family onset**. It is not successful-compromise lead time unless independently verified compromise timestamps are supplied.

## Current execution status

The V53 code and regression tests are frozen on branch `v53-offline-unknown-attack-stress`, but the full benchmark has **not yet executed successfully**.

GitHub Actions run `35121138991` failed twice before any workflow step started. Both attempts reported an unassigned hosted runner (`runner_id=0`, empty step list). A second run, `35121564268`, pinned the job from `ubuntu-latest` to `ubuntu-24.04` and removed setup-python caching; it again failed before any step executed. This isolates the current blocker to hosted-runner/account infrastructure rather than a model/test result.

Therefore no V53 recall, FPR, event-recall, or lead-time number is claimed yet. Existing V48 metrics remain the authoritative unseen-family evidence until V53 receives compute and produces an immutable evidence artifact.

## Safety and claim boundary

- no live attack traffic is generated;
- no external target is scanned or attacked;
- no automatic containment is approved by this benchmark;
- no V53 metric may be promoted until the frozen three-seed run actually completes;
- V53 outcomes must not be used to tune the same holdout and then relabel it as fresh evidence.
