# Core pipeline update — 13 September 2026

## Outcome

This update fixes evaluation/training defects and adds an on-premise shadow collector. It does **not** establish reliable unseen-attack forecasting or approve enterprise blocking. Neither new experimental checkpoint replaces the existing default.

## Implemented

1. **Validation-only monotone Platt calibration.** Test labels never fit the calibrator or policy. Class weighting is computed from training labels only. Input scaling remains fixed physical/log transforms, with no dataset-fitted normalization.
2. **1% validation false-positive budget**, replacing the new training path's previous 5% budget. Policies with no useful validation operating point are explicitly disabled. Per-family results include positives, negatives, unknown targets and descriptive exact binomial intervals. These intervals do not remove dependence between overlapping windows.
3. **Masked unknown-label supervision.** Contiguous observed network states are retained even when some traffic labels are unknown. Unknown labels have zero risk-loss contribution and are never changed to benign. Any-horizon targets are positive if a known positive exists, benign only if every future label is known benign, otherwise unknown. Invalid capture windows and time gaps still exclude sequences.
4. **New frozen capture-day evaluation.** The original 15-Feb-2018 DoS victim PCAP was selected and the v6 checkpoint hashes/thresholds frozen before retrieval. Downloaded ZIP member size: 189,153,280 bytes; CRC verified. The v6 model was not tuned after the result. Subsequent v7 masked-label experiments use the previously inspected four-day development benchmark and are not fresh-holdout claims.
5. **Annotation readiness audit.** Counts real known/unknown stage labels and incident records; produces a concrete review list. Existing supervised stage-head training and incident-level evaluation remain available, but cannot be validly trained/evaluated without reviewed annotations.
6. **Local shadow collector.** Consumes atomically completed `.pcap.ready` / `.csv.ready` files, parses traffic and runs the matching checkpoint locally. Stores scores/withheld outcomes in SQLite, deduplicates by capture/model hash, applies retention on writes, rejects symlinks and changed captures, and never publishes a blocking policy. It processes the last contiguous history of each completed capture, not every packet in real time.

## Actual measurements

### Frozen v6 model on new DoS capture

42 eligible examples: 14 positive, 28 negative, using schedule-assisted weak labels. The published wall-time timezone is still an unverified UTC-04:00 assumption. No independently verified compromise or stage labels exist.

| Model | False positives | FPR | Recall | State MSE |
|---|---:|---:|---:|---:|
| LSTM | 25 / 28 | 89.29% | 100% | 0.047820 |
| GNN + LSTM | 27 / 28 | 96.43% | 100% | 0.047750 |

GNN state-error difference versus persistence: −0.001048; descriptive paired block-bootstrap 95% interval [−0.001762, −0.0000194]. Versus LSTM: interval [−0.000284, −0.00000742]. This is narrow evidence of better state prediction on this one capture, not a generalization guarantee. Only 200 bootstrap replicates and one source day were used. The false-positive release gate fails decisively.

Full provenance, preprocessing exclusions and outputs: `datasets/ids2018/fresh_holdout/evaluation.json` and `frozen_protocol.json`.

### Masked-label v7 diagnostic on existing four-day benchmark

Retained sequence counts: train 267, validation 271, test 162. Clean-history examples with a known future malicious-flow window: train **2**, validation **3**, test **0**. These are flow-label events, not verified pre-compromise examples.

GNN botnet test: 41/41 negatives falsely alert (100% FPR); infiltration has 11 positive examples and no negatives, so its FPR is undefined. The early-warning validation policy found no useful operating point and is disabled. Its zero false alerts must not be described as successful defence. GNN state MSE is 0.021700 and LSTM 0.015417 on the retained v7 sequences. These sequence populations differ from v6 and cannot be used as a like-for-like improvement claim.

The useful fix is recovered supervision and correct accounting, not improved release performance.

## Reproduce

Install `garuda_v3/requirements.txt`. Training additionally uses SciPy through scikit-learn's dependencies; local serving/calibration application require only NumPy and the standard library.

```bash
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.train \
  --graphs datasets/ids2018/labelled/Thursday-22-02-2018.npz datasets/ids2018/labelled/Friday-23-02-2018.npz datasets/ids2018/labelled/Thursday-01-03-2018.npz datasets/ids2018/labelled/Friday-02-03-2018.npz \
  --split-manifest datasets/ids2018/split.json --decoder residual \
  --epochs 20 --history 8 --horizon 4 --stride 2 \
  --calibrate --balance-risk --allow-unknown-labels --fpr-budget .01 \
  --output garuda_v3/artifacts/your_new_run

python -m unittest discover -s garuda_v3/tests -p 'test*.py'
```

For the frozen fresh evaluation, inspect the existing report. `python -m garuda_v3.fresh_evaluation` refuses to overwrite a consumed evaluation. An independently obtained evaluation needs a new predeclared protocol and different untouched capture, not deletion of this record.

## Local shadow collection

```bash
mkdir -p runtime/capture_inbox
python -m garuda_v3.shadow_agent \
  --artifacts garuda_v3/artifacts/calibrated_host_v6 \
  --inbox runtime/capture_inbox --database runtime/shadow.sqlite --once
```

Have an authorized local sensor write and close a capture outside the inbox, then atomically rename it to `capture.pcap.ready`. Keep the inbox writable only by the sensor/operator. The collector does not open a network service, intercept customer traffic, or change firewall rules. Default retention is 30 days, cleaned on new writes. A checkpoint/schema mismatch or insufficient complete windows produces a withheld outcome. Models remain research-only even when a score is emitted. The global score does not identify an attacker IP. Customer-specific TLS, sensor rotation, operational monitoring and security review are still required.

## What cannot honestly be marked fixed

- ≤1% cross-family false-positive rate and ≥80% recall together.
- Verified positive compromise warning lead time on enough held-out incidents.
- Supervised MITRE results: all five stages remain without reviewed training labels.
- Production enforcement approval or independent security review.

The next needed input is better representative development telemetry and independently reviewed, timezone-aligned incident/stage timelines. Repeatedly tuning against the already exposed test captures would invalidate fresh-evaluation claims.

Dataset source and schedule: https://www.unb.ca/cic/datasets/ids-2018.html ; https://registry.opendata.aws/cse-cic-ids2018/ . Dataset attribution and redistribution terms remain in `datasets/ids2018/README.md`.

## Verification

50 Python tests passed, including unknown-label risk-gradient masking, calibration policy semantics, existing API/security tests, and successful local packet-to-forecast shadow collection. The collector fixture is synthetic functional test traffic, not attack-detection evidence.
