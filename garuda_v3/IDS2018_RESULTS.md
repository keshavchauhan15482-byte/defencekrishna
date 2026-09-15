# Real-PCAP experiment — results and limitations

This update adds real original CSE-CIC-IDS2018 packet captures, an actual host/packet-trained GNN checkpoint and an exploratory cross-family evaluation. It **does not establish reliable unseen-attack detection, verified pre-compromise warning, or supervised MITRE-stage accuracy**.

Data/provenance and reproduction: `datasets/ids2018/README.md` (from project root). Source and license: https://www.unb.ca/cic/datasets/ids-2018.html and https://registry.opendata.aws/cse-cic-ids2018/ .

## What ran

- Four selected captures from 22-Feb, 23-Feb, 1-Mar (part 2), and 2-Mar; one matching Ubuntu log; original member CRC and SHA-256 provenance.
- 1,549 observed packet/host graph windows before sequence selection. TTL, flags, TCP window, IAT and directed endpoint relationships come from actual packets. 64-node capacity supports the observed maximum of 51 hosts without truncating topology.
- Conservative removal of incomplete/offload-invalid windows. No time gaps filled.
- Schedule-assisted weak labels with documented UTC-04:00 alignment assumption. Unknown windows stay unknown; stage and successful-compromise labels remain unavailable.
- Train/validation/test: 226 / 232 / 77 examples. Each uses eight observed one-minute windows and predicts the next four. Web captures train/validate; botnet and infiltration are held out. Seed 42, 20 epochs, validation-selected checkpoint and thresholds. No retraining to optimize this test score.

## Ungated held-out results

| Model | F1 | Precision | Recall | False-positive rate |
|---|---:|---:|---:|---:|
| Logistic regression | 0.6491 | 0.4805 | 1.0000 | **1.0000** |
| Residual LSTM | 0.6491 | 0.4805 | 1.0000 | **1.0000** |
| Residual GNN + LSTM | 0.6491 | 0.4805 | 1.0000 | **1.0000** |

All three models predict positive for all 77 examples: 37 positive examples detected and **40/40 negative examples falsely alerted**. Recall alone is therefore misleading. The GNN state MSE is 0.01348018 versus 0.01340974 persistence; persistence is slightly better. These results do not improve the prior service-model benchmark and are a different task/data split, so the scores cannot be compared as a simple upgrade.

There are zero eligible clean-history future-positive examples after conservative unknown/gap exclusions, and no verified compromise timestamps. Incident warning performance is not measurable here. MITRE-stage labels were not invented from attack family names.

Likely contributing limitations include training only on one web victim/day, Linux-to-Windows/sensor differences, substantially different graph/activity distributions, and weak labels. These are hypotheses; no causal ablation identifies a sole cause. The original service-model results were also too narrow to support broad enterprise claims.

## Input-support abstention diagnostic

A robust history-summary support check was added after observing the holdout failure. Its center/scale use training inputs, and its cutoff uses the validation 99th percentile, with no test-score fitting. It is explicitly a **post-analysis development diagnostic**, not another blind test.

It abstains on 33/77 test examples and accepts 44/77 (57.1% coverage). The accepted subset still falsely alerts on **39/39 negative examples**. Thus this gate does **not** solve generalization. Abstention is reported as unknown; it is not counted as a correct negative, detected attack, or prevented compromise. The API withholds predictions outside support and the replay route handles that explicitly.

## Integration status

- Default demo remains `artifacts/residual_run`, the preceding service-graph checkpoint. The failed host checkpoint is not promoted and never enables automatic blocking.
- Research checkpoint and complete metrics: `artifacts/ids2018_host_run`. `support_gate.json` has an integrity hash, alongside checkpoint hashes.
- Optional inspection: `python -m garuda_v3.server --artifacts garuda_v3/artifacts/ids2018_host_run`. The first held-out replay may correctly show that prediction is unavailable outside training support. See raw benchmark files for the ungated results.
- PCAP/CSV ingestion now uses the loaded checkpoint's window size and node capacity, preventing silent 10-second/32-node mismatch for the new 60-second/64-node checkpoint.

## What is needed next

Use diverse normal traffic and multiple independent campaigns in training, not one web victim/day. Resolve timezone and flow-label alignment against authoritative logs. Obtain explicitly annotated tactic transitions and successful compromise events. Reserve a new untouched campaign after changing the model or data strategy. Reevaluate false alarms, precision, lead time and coverage together. Do not relabel reviewed test data or pick a threshold on its results to manufacture an improved score.

There is no dataset of “all zero-day attacks.” These are known controlled-testbed attack scenarios. Unseen-family evaluation is a useful limited experiment; passing it would still not guarantee zero-day coverage. This experiment did not pass.
