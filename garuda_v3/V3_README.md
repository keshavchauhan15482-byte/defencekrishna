# Garuda v3 model card and developer guide

Current update details and required data: [FIX_STATUS.md](FIX_STATUS.md). Original checkpoints remain under `artifacts/run`; the demo defaults to `artifacts/residual_run`.

## Scope

A trained directed GraphSAGE + LSTM world-model reference, implemented with NumPy reverse-mode differentiation. This is real supervised gradient training through graph layers, recurrent gates and autoregressive decoder. It is not the old handwritten approximate-gradient model, not PyTorch Geometric, and not a claim of research novelty. An accessible CPU implementation is appropriate for the offline SIH demo. A production backend can port the checked equations to a maintained ML framework after dependency access is available.

Inputs are 8 observed 10-second graph windows. Outputs are the next 4 graph-summary feature vectors, diagonal Gaussian standard deviations and per-window probabilities of malicious-flow presence. Autoregression feeds the previous predicted state into the next decoder step. The current residual decoder initializes at persistence and predicts a bounded change (±0.1 per step), clipped to the normalized feature domain. Its loss is BCE + 10×state MSE + 0.01×Gaussian NLL; optional masked stage BCE has weight 0.5. Older absolute-decoder checkpoints remain loadable. The model does not predict future graph edges, a causal compromise path or calibrated probability of infiltration.

## Data and features

`data.py` converts CIC CSVs into protocol/service graphs. Protocol nodes link to a fixed destination-service vocabulary using observed flow counts. This is an incidence graph, not host topology. Actual endpoint CSVs use `--mode host`; missing endpoints cause an error. Node features are permutation invariant under relabeling; learned host IDs are not features.

The supplied captures contribute 249,994 non-header records and 6,453 end-time graph windows. Friday labels are Bot/Benign; Thursday is Benign. Negative samples come from observed Benign labels, never unknown background. Both positive and negative classes are present in the chronological split, but class proportions change strongly over time. The included data is an uploaded subset, not the entire original dataset.

Features: log flow/byte/packet counts, mean duration, SYN/ACK/RST/FIN fractions, backward-packet ratio, TCP/UDP fractions, active mask, IAT mean, TCP window, packet TTL mean/variance, fragment and duplicate-payload-segment fractions, plus availability flags. Transforms use documented fixed scales in `summarize`. Missing packet attributes remain zero with availability=0, not fabricated TTL or port-entropy proxies. The CSV-trained model has no evidence for those packet dimensions; serving rejects packet-derived graphs with this checkpoint.

Flow-level IAT variance/max, payload-size distribution and richer scan-sequence features remain feature-expansion work; the current 21-dimensional schema does not cover every PS feature. Classic PCAP parsing supports Ethernet (including up to two VLAN tags) and raw IPv4. Unsupported link formats/PCAPNG fail explicitly. Non-IPv4 Ethernet traffic is skipped; a capture with no supported IP packets fails. Last packet bucket is omitted because it may be incomplete. Exact duplicate TCP payload segments indicate possible retransmission; there is no full TCP stream reconstruction.

Maximum graph size is 32 nodes in this reference. Larger host graphs require explicit sensor/subnet partitioning. The code fails instead of silently discarding hosts. Maximum CSV length is approximately 250,000 rows and 10,000 occupied windows. Limits are prototype capacity controls, not enterprise scaling claims.

## Reproduce

Run all commands from the project root after installing `garuda_v3/requirements.txt`.

```bash
python -m garuda_v3.data ntro-world-model/cicids2018_data/Thursday-01-03-2018_Infiltration.csv --output garuda_v3/artifacts/Thursday.npz
python -m garuda_v3.data ntro-world-model/cicids2018_data/Friday-02-03-2018_Infiltration_REAL.csv --output garuda_v3/artifacts/Friday.npz
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.train --graphs garuda_v3/artifacts/Thursday.npz garuda_v3/artifacts/Friday.npz --epochs 20 --seed 42 --decoder residual --output garuda_v3/artifacts/reproduced
python -m garuda_v3.server --artifacts garuda_v3/artifacts/reproduced
```

Use a new output folder; replacing a checkpoint also requires its matching metrics/hashes. Reference runs 7 and 19 use the same configuration except seed and output directory. The published primary checkpoint remains seed 42, rather than the best test seed. This residual architecture change follows inspection of the earlier holdout, so its results are explicitly development comparisons. Checkpoint selection within each new run still uses validation only.

The loader uses NPZ with `allow_pickle=False`. `ForecastService` checks the artifact hash against metrics before serving. This detects accidental/isolated checkpoint modification; it is not a trusted model-signing authority, because an attacker able to modify both files could change both. Production needs a protected model registry/signing key.

## Evaluation interpretation

Raw chronology splits at 60% and 80%. Each sequence stays within one capture and split, and each future target follows its context. Gaps break sequences. Batches can shuffle only training examples. Validation loss selects model epoch; validation F1 selects the risk threshold. The final-window LR baseline receives the same pooled feature history and cutoff. Thus it has equal temporal observations but no graph-edge input; GNN advantage can reflect topology as well as architecture. LSTM is the temporal ablation. Removing graph edges at inference is a sensitivity test, not a separately trained no-edge baseline.

The primary test has 160 examples and 121 positives at the fourth future horizon. Residual GNN F1 94.9% exceeds LR 91.6% but is below residual LSTM 95.8%, but there are only 39 negative examples. GNN FPR 5.1% is not acceptable evidence for broad automatic blocking. Adjacent examples overlap; block-bootstrap intervals and three-seed dispersion are diagnostic, not cross-campaign generalization.

Only one clean-history test example has a positive final future window. All models miss it. Zero unique onset alerts were found using clean contexts. A diagnostic using last observed ground-truth labels yields high persistence scores, showing sustained attack episodes dominate. That diagnostic is not deployable without a detector. No claim of advance compromise warning is supported.

Residual state forecasting improves substantially relative to the original absolute decoder: primary GNN MSE is 0.0127064 versus 0.0127354 persistence and 0.0120477 residual LSTM. All three GNN seeds beat persistence on this internal sample, but the primary paired interval crosses zero. Strong state-dynamics superiority is not established. Training joint negative log likelihood can produce negative loss values (a density may exceed 1); this is mathematically valid and does not mean negative classification error. Gaussian interval coverage is empirical and does not prove calibrated risk scores.

## Inference, explanation and stage labels

`server.py` serves the static dashboard and authenticated APIs locally. `inference.py` validates exact feature schema, graph mode, shapes, masks, finite ranges and chronological history. It does not accumulate cross-user forecast state. Both graph upload and replay use the trained checkpoint.

The explanation is gradient-times-input for the highest-risk forecast horizon, across the actual observed sequence. The UI reports magnitude rankings; JSON retains signed contributions. These are local sensitivities, not SHAP, causal attribution or proof of attack progression. Stages remain unknown for the supplied checkpoint because its labels cannot train stage prediction. `annotations.py` and `--stage-supervision` implement a five-tactic multi-label head. Unknown annotations are masked rather than treated as negative targets. The trainer retains stage metrics and the API can serve the supervised stage trajectory after retraining. Tactics are objectives, not an ordered kill chain. See FIX_STATUS.md for exact data and command requirements.

PCAP/host graph ingestion can succeed while inference remains unavailable due to mode/packet-training mismatch. This is an intentional schema gate. The UI displays the graph and the reason. There is no synthetic fallback and no untrained random head.

## Authenticated response and WAF integration

The UI defaults to dry-run and never auto-blocks based on this model. Separate locally generated tokens control viewer and operator routes. The service binds to loopback and checks Host/Origin. Bodies, worker concurrency and operation rate are bounded. Credentials stay in `garuda_v3/runtime/access.json` with mode 0600 and are excluded from archives. Avoid copying this runtime folder into submissions.

For an owned lab only, configure `GARUDA_ALLOWED_CIDRS`, a strong `GARUDA_POLICY_KEY`, and `GARUDA_ENFORCE=1` before starting the v3 service. Start the existing Node proxy with the same signing key and `GARUDA_POLICY_FILE` pointing to the runtime policy.json. A trusted outer proxy must strip/replace forwarded headers; only its exact socket IPs belong in `TRUSTED_PROXY_IPS`. No proxy IP is trusted by default.

An operator can submit an allowed IP, reason and TTL of 10..900 seconds. The service writes an atomic HMAC-signed policy file. The WAF verifies it before applying an expiring IP restriction. Revoke and kill-switch actions remove v3 policies. The success response says publication still needs proxy confirmation; the local integration test verifies actual 403 and subsequent restoration. This is application-proxy enforcement, not an OS firewall or complete network IPS.

SQLite audit events form a hash chain. This detects record modification but not full-chain replacement or truncation without external anchoring. It is not a blockchain consensus system. Invalid policy files disable only the optional v3 policy overlay, avoiding blanket outage while retaining the legacy WAF. Deployment monitoring should alert on this fail-open condition.

## Open production gates

- Endpoint-preserving, packet-derived and attack-stage-labelled training data.
- Multiple unseen campaigns/days, meaningful onset cases and compromise timestamps.
- Lower operational false alarms, risk calibration and improved state error over persistence.
- Maintained production ML backend, versioned graph schema and regression parity.
- TLS gateway, identity provider, rotated credentials, per-user/tenant audit and quotas.
- Durable signed model registry, protected audit anchoring, backup/recovery and retention.
- Independent security review, load tests and chaos/failure drills.
- Original-source and dataset-license/provenance review before public release.

The new code is suitable for an honest engineering demo, not a numerical claim of 8-9/10 market readiness. A local test suite cannot prove enterprise safety or guarantee a prize.
