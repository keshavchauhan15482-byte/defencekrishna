# V8: broader development training and continuous gauge

## Delivered

The hosted risk gauge now starts automatically, loops at the last recorded frame, resumes after backgrounding and preserves an intentional manual pause. Both risk charts advance from recorded model outputs. There is no live customer sensor connected to the hosted page. Eleven server/frontend tests pass, including playback lifecycle coverage.

The host-model experiment now trains with web, botnet and DoS captures rather than web-only development. Each development capture uses an initial 70% training segment and a later validation segment, separated by a 12-window embargo. All sequence windows are checked for overlap and continuity. The 28-Feb infiltration victim capture remains outside both development splits. Input normalization remains fixed physical/log transforms; class weights use training labels; monotone calibration and thresholds use validation only. Unknown labels remain masked.

`datasets/ids2018/diverse_v8/protocol.json` records the predeclared capture and experiment. The two old benchmark botnet/DoS captures are now explicitly development data, so their earlier holdout designation does not apply to this model. Do not use them for new independent performance claims.

The initial victim capture part had only eight evaluable benign examples and no positives. Its GNN had zero false alerts, but recall was unmeasurable. The remaining victim capture was acquired as an explicitly recorded extension using the same frozen weights and thresholds, with no refit.

## Larger-capture diagnostic

The remaining original PCAP is 347,870,553 bytes; its official archive-member CRC and SHA-256 were verified using bounded streaming extraction. The combined raw-data addon also contains the 98,445,934-byte initial part.

The larger capture contains 424 graph windows and up to 80 observed hosts. This exceeds the trained 64-node schema. The originally planned 64-node extension evaluation was therefore **blocked**. A separate 256-node diagnostic was run against the unchanged node-count-independent model implementation. This deviation is recorded in `diverse_v8_extension/scale_deviation.json`; it is **not** a passed predeclared holdout or approval to relax production inference validation.

Across 207 contiguous sequence examples, 189 any-horizon targets were known (56 positive, 133 negative), and 18 remained unknown and were excluded from labelled metrics.

| Any-horizon alert policy | False positives | FPR | Recall |
|---|---:|---:|---:|
| LSTM | 109 / 133 | 81.95% | 100% |
| GNN + LSTM | 18 / 133 | 13.53% | 53.57% |

GNN FPR descriptive 95% binomial interval: [8.22%, 20.54%]; recall interval: [39.74%, 67.01%]. Correlated windows and weak labels limit these intervals. The 1% FPR / 80% recall gate fails. These results must not be described as a direct 96.4% → 13.5% improvement: the old DoS test and this infiltration diagnostic are different populations.

For the separate last-horizon target, 182 examples were known (44 positive, 138 negative):

| Model | F1 | Precision | Recall | FPR |
|---|---:|---:|---:|---:|
| Logistic regression | 42.72% | 27.16% | 100% | 85.51% |
| LSTM | 42.11% | 26.67% | 100% | 87.68% |
| GNN + LSTM | 44.71% | 46.34% | 43.18% | 15.94% |

The dedicated clean-history early-warning policy remains disabled because validation had no useful operating point under its budget. On this diagnostic it missed the one known clean-history future-positive example. Zero false alerts from a disabled policy are not successful defence.

GNN's paired state-error difference versus persistence has a bootstrap interval crossing zero: [−0.000160, +0.000517]. No significant state-forecast improvement is asserted on this capture.

## Not solved

- Reliable early warning before verified compromise: no independently verified compromise timestamps.
- Supervised MITRE stages: no reviewed positive/negative tactic timelines. No synthetic or schedule-derived stage labels were passed off as ground truth.
- Required cross-family FPR and recall together.
- Independently reviewed enterprise enforcement or live hosted network ingestion.

These experimental checkpoints remain separate from the default demo model and are not production-approved.

## Use and reproduce

The main project ZIP includes code, graph datasets, model weights and results. The optional `KrishnaDefence_PCAPPack_V8.zip` contains the two additional original PCAP parts. Extract it into the same parent directory as the main project to merge its `KrishnaDefence/datasets/ids2018/...` paths. Derived cleaned V8 captures are reproducible and omitted from the downloads.

```bash
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.train \
 --graphs datasets/ids2018/labelled/Thursday-22-02-2018.npz datasets/ids2018/labelled/Friday-23-02-2018.npz datasets/ids2018/labelled/Friday-02-03-2018.npz datasets/ids2018/fresh_holdout/labelled_graph.npz datasets/ids2018/diverse_v8/labelled_graph.npz \
 --split-manifest datasets/ids2018/diverse_v8/protocol.json \
 --evaluation-scope development_reused_holdout --decoder residual \
 --epochs 20 --history 8 --horizon 4 --stride 2 \
 --calibrate --balance-risk --allow-unknown-labels --fpr-budget .01 \
 --output garuda_v3/artifacts/your_new_v8_run
```

The original V8 run was predeclared; reproducing it after seeing these results is an exposed-data reproduction, hence the command above labels that scope honestly. `garuda_v3/evaluate_v8_extension.py` verifies the frozen checkpoint hashes and refuses to overwrite existing results. Inspect the shipped report rather than deleting it to claim another fresh evaluation.

Graph preparation supports an explicit 64/128/256/512-node capacity and preserves actual nodes. PCAP cleaning now commits a completed derivative atomically so downstream parsing cannot observe a partly written output. Large-member extraction has size limits, chunked decompression, CRC checks, cleanup on failure and tests.

Verification: 55 Python tests in total, including split overlap/embargo checks, masked supervision, calibration, shadow collection and bounded-stream integrity. No independent security review is claimed.

Dataset and published schedule: [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html). Labels remain schedule-assisted weak supervision, including an unverified UTC-04:00 convention; attack start does not establish compromise. Required original attribution remains in `datasets/ids2018/README.md`.
