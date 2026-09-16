# V48 fresh ToN-IoT unseen-family result

V48 froze a hybrid unseen-family design before inspecting ToN-IoT outcomes: 75% temporal known-family LSTM risk + 25% future-world novelty, with a benign-only 0.5% policy FPR reserve and a release gate of FPR <=1% / recall >=80%.

## Source and integrity

The first community ToN-IoT train/test mirror was rejected because its 44-column derivative omitted the timestamp. V48 did **not** treat CSV row order as time. The workflow then selected a timestamp-preserving public ToN-IoT variant only after schema audit verified `ts`, `src_ip`, `label`, and `type`.

Accepted source:

- 461,043 rows / 45 columns
- 69,861,203 bytes
- SHA-256 `65d5465df1809b984fd10e4703bc9c012d1aefd11803773856364216f0a3520d`
- timestamp field: `ts` (epoch seconds)
- 10 strict numeric network fields before minute aggregation
- 34,435 source-minute states
- 10,953 contiguous 8-minute histories with four future minutes

## Support result

The final chronological ToN-IoT tail contains **1,729 clean benign future sequences but zero future-positive sequences for every available attack family**:

- backdoor: 0 positives
- dos: 0 positives
- injection: 0 positives
- mitm: 0 positives
- password: 0 positives
- ransomware: 0 positives
- scanning: 0 positives

Therefore no family is eligible for the frozen unseen-family evaluation and no model metric is produced from this dataset/split. `all_selected_hybrid_release_gates_passed` is false and clean-history positive support is absent.

## Interpretation

This is an evaluation-support limitation, not a model failure or success. The sample's chronological final tail is unsuitable for a forward-time held-out-family benchmark. Moving the split after seeing family locations or treating row order as time would weaken the evidence, so V48 refuses both.

The frozen hybrid implementation and tests remain useful, but ToN-IoT `Train_Test_Network` cannot be used as the final forward-time unseen-family proof under this protocol. The next fresh test must use an attack campaign/day that naturally contains benign prehistory followed by a family excluded from development.

## Claim boundary

V48 does not support a zero-day, unseen-family recall, pre-onset warning, or compromise-lead-time claim. Automatic containment remains disabled.

GitHub Actions run `35091178530` completed the timestamp-preserving download, schema tests, support audit, summary and evidence artifact successfully; full Krishna integration CI also passed on the same head.
