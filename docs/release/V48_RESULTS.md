# V48 unseen-family evidence results

V48 contains two complementary evidence tracks. The earlier ToN-IoT chronological audit is retained because it correctly refused to manufacture an unseen-family result when the final tail had no attack positives. The **authoritative alert-fusion result** is the later canonicalized X-IIoTID reserve-family run described below.

## 1. Authoritative frozen X-IIoTID reserve result

This is the current V48 result for unseen-family alert generalisation.

- GitHub Actions run: `35107130823`
- evaluated code head: `a129654908ac767188837a9de352fd7ed5980029`
- seeds: `42, 43, 44`
- history: 8 minutes
- forecast horizon: 4 minutes
- release gate: validation state model beats persistence, test FPR <=1%, test recall >=80% on **every seed**
- runtime/model evidence: strict network-only X-IIoTID fields
- attack-family labels: split/evaluation metadata only, never model inputs

### Canonical family boundary

Before any family-disjoint split, family labels are canonicalized by case-folding, converting underscores to spaces and collapsing repeated whitespace. This makes spellings such as `Lateral _movement` and `Lateral Movement` one family identity.

All V47-published families are permanently development-only:

- `tampering`
- `lateral movement`
- `weaponization`
- `exfiltration`
- `reconnaissance`

The support-qualified reserve families selected before score development are:

- `exploitation`
- `c&c`

Reserve isolation is fail-closed:

- reserve/overlap sequences excluded from model fitting: **true**
- reserve/overlap sequences excluded from fusion-selection metrics: **true**
- overlap embargo: **12 sequence steps on each side**
- blocked sequences: **2,988**
- reserve metrics used for score selection: **false**

### Frozen alert configuration

The configuration was selected only from already-exposed development families and serialized before reserve metrics were computed.

- 75% `known_attack_transfer`
- 25% `transition_energy`
- 0% `future_state_novelty`
- 0% `predicted_delta_novelty`
- 0% `history_state_novelty`
- benign policy budget: **0.25%**
- selected candidate: `transfer75_transition_energy25`
- frozen config SHA-256: `4b1a25da56bfd7b7e07e9ae542cf9993485be8437924d479536415508889ad6a`

### Reserve-family metrics

| Reserve family | Recall mean ± SD | FPR mean ± SD | Precision mean | F1 mean | State gate 3/3 | Unseen gate 3/3 |
|---|---:|---:|---:|---:|---|---|
| Exploitation | **91.88% ± 0.60 pp** | **0.390% ± 0.042 pp** | **97.08%** | **94.41%** | PASS | **PASS** |
| Command & Control (`c&c`) | **87.63% ± 2.69 pp** | **0.366% ± 0.000 pp** | **97.02%** | **92.08%** | PASS | **PASS** |

Both reserve families satisfy the project's requested **FPR <=1% and recall >=80%** gate on all three seeds, and every reserve state model passes the validation persistence gate.

`all_reserve_unseen_gates_passed = true`

This is materially stronger than V47: the alert layer now converts transferable known-family evidence plus world-model transition dynamics into a low-FPR signal that passes the frozen unseen-family gate on two reserve families.

### Invalid exploratory alias run

GitHub Actions run `35105863772` is **invalid for unseen-family evidence**. Before canonicalization, X-IIoTID spelling `Lateral _movement` was treated as distinct from the V47 development label `Lateral Movement`, so the same semantic family could enter the reserve set. Its reserve metrics must not be cited.

The alias bug was fixed and regression-tested before authoritative run `35107130823`. In the authoritative run, `lateral movement` is development-only and the reserve set is only `exploitation` and `c&c`.

## 2. Earlier ToN-IoT chronological support audit

V48 also tested whether a fresh timestamp-preserving ToN-IoT source could provide a forward-time unseen-family holdout without manipulating the split.

Accepted source characteristics:

- 461,043 rows / 45 columns
- SHA-256 `65d5465df1809b984fd10e4703bc9c012d1aefd11803773856364216f0a3520d`
- timestamp field: `ts`
- 34,435 source-minute states
- 10,953 contiguous 8-minute histories with four future minutes

The final chronological tail contained **1,729 clean benign future sequences but zero future-positive sequences for every available attack family**. Therefore the workflow correctly produced no unseen-family model metric from that split. It did not reorder rows, move the split after inspecting attack positions, or reinterpret unknown/unsupported samples.

That remains useful negative evidence: this ToN-IoT sample is unsuitable for the strict forward-time held-out-family proof under the frozen protocol.

## Claim boundary

V48 supports this controlled claim:

> A frozen Garuda fusion generalized to two public-dataset attack families excluded from V48 model fitting, calibration, policy selection and fusion-score development, while satisfying the project's <=1% FPR / >=80% recall gate across three seeds.

V48 does **not** establish:

- detection of a truly undisclosed real-world zero-day;
- verified pre-compromise warning lead time;
- successful prevention of compromise;
- validated MITRE stage-transition timing;
- autonomous enterprise containment readiness.

Those stronger claims require newly reserved independent campaigns with verified attack onset, outcome and compromise timestamps plus clean pre-attack histories. The V48 Exploitation and C&C outcomes are now exposed evidence and must never be tuned against and then relabelled as a fresh holdout.
