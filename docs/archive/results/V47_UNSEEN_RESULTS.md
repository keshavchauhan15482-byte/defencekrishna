# V47 — Unseen-family / zero-day-like generalisation results

This report records the first strict network-only X-IIoTID benchmark in which an attack family is excluded from model development and used only for evaluation. It is an **unseen-family simulation**, not proof of an undisclosed real-world zero-day and not verified pre-compromise lead-time evidence.

## Data and protocol

- X-IIoTID: **820,834 rows / 68 columns**, SHA-256 `7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0`.
- Strict network-only numeric inputs: **21 raw fields** (`Scr_port`, `Des_port`, duration, byte/packet volumes and ratios, missed bytes, SYN/SYN-ACK/pure-ACK/payload/FIN-or-RST indicators, rate and RTT-adjacent network fields where available).
- System-resource, process/file, OSSEC/alert, login, attack/class labels and learned IP identifiers are excluded from model input.
- 68,020 source-minute states -> **30,297 contiguous 8-minute histories with four future minutes**.
- Seeds: **42, 43, 44**.
- Held-out family never appears in train, state-validation, benign-reference or policy fitting. Neighboring overlapping sequence cutoffs are embargoed.
- The world model predicts the next four network states. Open-set risk is the distance of that predicted future trajectory from a clean-benign forecast manifold. The policy threshold is selected from clean benign policy data under a 1% empirical FPR budget.
- A known-attack logistic history classifier is evaluated on the same held-out-family positives and 1,366 clean benign negatives.

## Track A — strict chronological pre-onset audit

The strictest test asks for a family that is absent from the complete observed history and then first appears in the future chronological test block.

**Result: no supported attack family exists in the final chronological block.** Every coarse family has `test_positive = 0` while the block contains 1,366 clean benign negatives. Therefore X-IIoTID cannot establish a chronological unseen-family onset forecast under this 8+4-minute protocol. No synthetic onset or relabelled attack window was created.

This is an evaluation-support limitation, not a model success/failure result.

## Track B — leave-one-family-out unseen-family generalisation

Five families were selected by positive support only, never by model performance. Each family has zero development exposure in its own run.

| Held-out family | Positive sequences | Clean-history onset positives | World state test MSE vs persistence | World open-set recall mean ± SD | World FPR mean ± SD | Known-family logistic recall | Logistic FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| Tampering | 1,876 | 0 | **0.3146 vs 0.4996** | **0.00% ± 0.00** | 3.343% ± 1.901 | 87.42% | 3.367% |
| Lateral Movement | 1,598 | 0 | **1.0852 vs 1.4184** | **32.67% ± 0.49** | **0.317% ± 0.042** | 57.45% | 1.391% |
| Weaponization | 557 | **6** | **0.2999 vs 0.3956** | **12.15% ± 6.21** | **0.317% ± 0.042** | 98.38% | 2.782% |
| Exfiltration | 471 | 0 | **0.2688 vs 0.4070** | **0.00% ± 0.00** | **0.390% ± 0.085** | 99.79% | 2.050% |
| Reconnaissance | 364 | 0 | 1.0601 vs **0.9978** | **16.85% ± 5.87** | **0.415% ± 0.112** | 40.66% | 1.611% |

### State-model finding

The learned world model beats persistence on the held-out-family evaluation states for **4 of 5** evaluated families:

- Tampering: **37.04% lower** test state MSE than persistence.
- Lateral Movement: **23.49% lower**.
- Weaponization: **24.18% lower**.
- Exfiltration: **33.95% lower**.
- Reconnaissance: **6.24% worse** than persistence; the validation persistence gate also fails in all three seeds.

This is useful evidence that generic network-state dynamics can transfer to several unseen attack families. It is **not** sufficient attack-warning evidence by itself.

### Unknown-attack warning finding

The future-trajectory anomaly policy does **not** reach the project release target. Where FPR is low (roughly 0.3–0.4%), recall is only 0–33%. Tampering has both 0 recall and FPR above 1%. Therefore **no held-out family passes FPR <= 1% and recall >= 80% across all seeds**.

The known-family logistic classifier transfers surprisingly well to some unseen families (Tampering 87.42%, Weaponization 98.38%, Exfiltration 99.79% recall), but its observed benign FPR is 1.39–3.37%, above the requested 1% gate. It also performs poorly on Lateral Movement and Reconnaissance. It is therefore not a release-grade zero-day detector either.

### Pre-onset evidence

Only Weaponization contains any clean-history onset support: **6 sequences**. The world open-set policy detects **0/6** in every seed at approximately 0.29–0.37% FPR. All other selected families have zero clean-history onset positives.

Accordingly:

- unseen-family generalisation: **measurable but insufficient**;
- strict pre-onset unseen-family forecasting: **not demonstrated**;
- verified pre-compromise lead time: **not established**;
- real zero-day claim: **not supported**;
- automatic unknown-attack containment: **not approved**.

## What V47 teaches us

V47 separates two different problems that must not be mixed:

1. **Unseen-family recognition/generalisation** — can a model trained on other attack families identify novel malicious dynamics after/while the new family appears?
2. **Pre-onset forecasting** — can it warn while the complete observed history is still clean, before the unseen attack begins or compromise completes?

The current network-only world model is much stronger at **state prediction** than at turning a predicted trajectory into an unknown-attack alert. The next useful model change is therefore not a larger decoder or more epochs. It is a stronger family-agnostic risk layer that consumes both observed history and world-model forecast features, trained only on known families, with benign-only calibration and a family-disjoint final evaluation.

## Reproduction

GitHub Actions workflow `V47 unseen-family open-set diagnostic`, run `35089301491`, completed successfully. The same PR head also passed the complete Krishna Defence integration CI. Raw X-IIoTID is downloaded by the workflow and is not committed to the repository.
