# Three requested fixes — 11 September 2026

**Later update:** Real IDS2018 PCAPs and a host/packet-trained research checkpoint have now been added. Their unseen-family benchmark failed; no MITRE/compromise evidence was established. Read `IDS2018_RESULTS.md`; descriptions below of missing raw PCAP/host training refer to the preceding residual revision.

## What changed

| Issue | Implemented and checked | Evidence still required |
|---|---|---|
| Pre-compromise warning | Verified-incident evaluator counts eligible cases, missed incidents, uncovered incidents and warning lead times. Separate any-horizon alert thresholds are selected on validation with a 5% validation FPR budget. Clean-history warning calibration explicitly reports insufficient classes. Campaign-held-out split manifests reject overlap. | Real incident timestamps and enough independent clean-history future positives. Existing validation has zero such positive examples; test has one and it is still missed. No verified compromise annotations were supplied. |
| Weak state forecasting | Residual autoregressive decoder starts at persistence, learns bounded changes, and trains with BCE + 10×state MSE + 0.01×Gaussian NLL. All three existing seeds were retrained. Per-feature, per-horizon, changed-entry and paired block-bootstrap diagnostics are included. | Fresh campaign evaluation. The primary improvement over persistence is small and its paired interval includes zero. |
| Host/packet and supervised MITRE model | PCAP/endpoint CSV + hash-bound timeline conversion, annotation-preserving graph datasets, masked multi-label stage loss, trained stage-head serialization, per-stage held-out metrics and stage inference are implemented. End-to-end synthetic-fixture training test passes. | Actual endpoint/packet telemetry and reviewed positive **and negative** stage labels. Bundled trained checkpoints remain service-graph, flow-trained models; test fixtures are not model-quality evidence. |

## Measured development comparison

Same supplied CSVs, same temporal split and seeds as the previous release. These test examples had already been inspected: this is a development comparison, **not a new blind test**. Epoch selection used validation joint loss. Seed 42 remains the primary demo model; the best test seed was not substituted.

| GNN model | Final-window F1 | State MSE | Persistence MSE |
|---|---:|---:|---:|
| Previous primary, seed 42 | 0.94421 | 0.05370656 | 0.01273543 |
| Residual primary, seed 42 | 0.94872 | 0.01270640 | 0.01273543 |
| Residual, seed 7 | 0.95319 | 0.01218163 | 0.01273543 |
| Residual, seed 19 | 0.97925 | 0.01202803 | 0.01273543 |

Primary state error fell about 76.3% relative to the old decoder, but is only 0.23% below persistence. The three-seed mean state MSE is 0.01230535 (about 3.38% below persistence). The primary paired MSE-difference bootstrap interval is [-0.00018444, +0.00017542]; it does not establish a reliable improvement by itself. Diagnostics use correlated internal examples, not independent attacks.

The retrained LSTM baseline has F1 0.95763 and state MSE 0.01204769, better than the primary GNN. Therefore adding graphs has **not** established superiority over LSTM on this service-only dataset. Graph structure needs useful host relationships and separate evaluation; architectural complexity is not evidence of better forecasting.

For the primary GNN, the ordinary final-window classifier threshold is 0.85. The deployed any-horizon alert threshold is 0.84015393, selected against any-positive future windows on validation, with a 5% validation false-positive budget. These are distinct targets. The any-horizon test has 123 positive examples and F1 0.95763; do not compare that score with the final-window LR F1 as if the targets matched.

## Train on real annotated telemetry

1. Obtain authorized endpoint-preserving PCAPs (supported classic PCAP Ethernet/raw IPv4), or CSVs with actual endpoints. The attached service CSVs cannot be converted into genuine host topology or missing packet observations.
2. Have a reviewer fill `examples/annotation_template.json` for each original capture. Replace every placeholder, including UTC epoch times. Bind the sidecar to the SHA-256 of the original bytes. Cite log/annotation evidence for reviewed coverage and successful compromise times. A malicious-flow label is not a compromise timestamp.
3. Label only reviewed intervals. An omitted stage stays unknown (-1). A stage value 0 asserts a reviewed absence; do not manufacture negatives from missing annotations. Boundary windows crossing annotation intervals remain unknown and are excluded. Stage objectives may coexist and are not forced into an ordered chain.
4. Convert each capture; unknown background is not automatically benign:

```bash
python -m garuda_v3.annotations capture-a.pcap --kind pcap --annotations capture-a.timeline.json --mode host --output graphs/capture-a.npz
```

For endpoint CSVs use `--kind csv`; packet training still requires actual PCAP-derived observations. Do not mix host and service schemas in one training run. Host graphs support at most 32 active hosts; partition larger captures explicitly.

5. Predeclare independent campaign assignments in a JSON manifest (see `examples/campaign_split_template.json`). Use several independent incidents per split; the three-name template is a schema example, not sufficient evidence. Never move the test cases after inspecting results.

```bash
python -m garuda_v3.train --graphs graphs/capture-a.npz graphs/capture-b.npz graphs/capture-c.npz --split-manifest split.json --decoder residual --stage-supervision --evaluation-scope new_predeclared_holdout --epochs 20 --output garuda_v3/artifacts/host_packet_run
python -m garuda_v3.server --artifacts garuda_v3/artifacts/host_packet_run
python -m garuda_v3.release_gate --artifacts garuda_v3/artifacts/host_packet_run
```

The `new_predeclared_holdout` flag documents your process; software cannot authenticate that a campaign was never seen. Preserve the original manifest and an external review record. Campaign IDs must correspond to genuinely independent captures, not renamed copies.

The trainer refuses a nonempty output directory. It stores actual packet-training availability, stage thresholds, annotation provenance, held-out stage probabilities, and test example indices. The API only shows supervised tactics with both-class training/validation support; unsupported tactics remain unreported. This availability check is weaker than a rigorous stage-performance validation, so inspect every stage's held-out counts and metrics.

## Remaining limits

Real host/packet checkpoint training, verified compromise-warning performance and independently validated stage predictions are still blocked by missing data, not declared complete. No synthetic data or probability-to-stage shortcut was used to fill that evidence gap. Some PS packet/flow attributes remain outside the 21-feature schema; see the model card. Market readiness remains false in `RELEASE_GATES.json`. No prize, external score, zero-flaw claim or enterprise readiness is guaranteed.
