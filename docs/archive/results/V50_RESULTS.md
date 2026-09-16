# V50 WUSTL-IIoT-2021 unseen-family support audit result

V50 audits whether WUSTL-IIoT-2021 can support a fresh clean-history unseen-family forecasting experiment under a fixed chronological protocol. No model is trained because the support gate does not pass.

## Source

- 1,194,464 rows / 49 columns
- 409,800,698 bytes
- SHA-256: `f897b24578cc6fdeb3e7a0e9ff63efd5bbdc926a545abbda725e0dbb348c6bca`
- timestamp: `StartTime`, parsed as datetime text
- family truth: `Traffic`
- publisher leakage exclusions enforced: `StartTime`, `LastTime`, `SrcAddr`, `DstAddr`, `sIpId`, `dIpId`
- 42 non-label numeric fields remain potentially eligible for a later network model, but none are fitted in this audit.

## Fixed temporal protocol

- 8-minute observed history
- 4-minute future horizon
- 60% train / 15% calibration / 10% policy / final 15% test
- 12-minute embargo between development partitions
- final-tail positive requires the held-out family to be absent from observed history and appear in the future
- clean-onset positive additionally requires the entire observed history to contain no attack-labelled traffic

The timestamped table yields 423 global source minutes, 412 complete history/future sequences and 50 final-test sequences.

## Support result

| Family | Family-free train | Family-free calibration | Family-free policy | Final-tail future positives | Clean-history future positives | Clean benign negatives |
|---|---:|---:|---:|---:|---:|---:|
| Backdoor | 247 | 12 | 29 | **0** | **0** | 50 |
| CommInj | 223 | 50 | 29 | **0** | **0** | 50 |
| DoS | 193 | 50 | 29 | **0** | **0** | 50 |
| Reconn | 210 | 50 | 29 | **0** | **0** | 50 |

All 1/2/3/4-minute horizon positive counts are zero for every family in the fixed final chronological tail.

The predeclared training permission requires at least 20 clean-history future positives, at least 100 clean benign negatives and adequate family-free development support. Therefore:

- `eligible_families_for_fresh_v50_model_test = []`
- `model_training_permitted = false`

## Interpretation

This is an evaluation-support limitation, not a model failure. Moving the split after observing where the attacks occur would turn the final holdout into a tuned diagnostic, so V50 refuses to do that.

WUSTL remains useful for conventional detection and development studies, but this public mirror/fixed final tail is not suitable for the next independent SIH pre-onset unseen-family proof.

## Reproduction

- V50 WUSTL support workflow: run `35093539054`, successful.
- evidence artifact: `v50-wustl-support-evidence`, digest `d00a190361aad24a9f621b2f39825d6c76234d59a4ee8b109939498dfaaeaff3`.
- full Krishna regression on the same PR head: run `35093538854`, successful.

No zero-day accuracy, recall, compromise lead time, MITRE-stage or autonomous-containment claim is made from V50.
