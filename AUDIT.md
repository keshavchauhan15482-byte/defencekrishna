> Initial v2 audit. The new implementation and current evidence are documented in `garuda_v3/V3_README.md`, `garuda_v3/VERIFICATION.md`, and the root README. Historical ratings below do not score the v3 revision.

# Krishna Defence: code and data audit — 11 September 2026

## Verdict

Substantial student prototype with a working HTTP inspection architecture, adaptive signature memory, dashboards, a handwritten LSTM runtime, PyTorch model definitions and data utilities. It is not yet an independently validated network attack forecasting product. A good SIH direction, but the largest gains now come from correct telemetry and reproducible future prediction rather than adding more model names.

Qualitative reviewer assessment, not measured performance: prototype breadth 7/10; demonstrated forecasting validity 3/10; commercial readiness 2/10. These scores describe the submitted evidence, not the team's potential. The fixes in this revision improve specific correctness/security paths; they do not establish new accuracy or production readiness.

Official PS verified at https://www.sih.gov.in/sih2026PS (SIH26153). It allows feature vectors or graphs and alternative sequence/graph architectures. GNN is not compulsory. The priorities are learned future state dynamics, interpretable progression predictions, both flow and packet features, offline operation and comparison with logistic regression. Original documents/presentation have legacy claims; this audit supersedes them.

## Findings, evidence and status

| Priority | Evidence in submitted source | Consequence / status |
|---|---|---|
| Critical | `proxy.js` served any existing project `.js`/`.json` through a public static-file branch | Source, model weights and learned memory could be downloaded. Removed branch. Four local HTTP regression requests verified these paths reach the upstream instead. |
| Critical | CSV timestamp used only minute/second | Different hours/days collapsed together. Full date/time parsing now preserves windows and rejects invalid timestamps. Existing weights need retraining. |
| Critical | `kfold_cross_validation.py` forecasts after seeing 16 windows but trains the decoder against input windows 1–8 | Reconstruction of observed history is not future forecasting. Added a separate future-only training entrypoint; legacy script remains unsuitable for claims. |
| High | `baseline_benchmark.py` gives LR only `seq[2]`, LSTM the entire sequence; label is any attack inside that sequence | Unequal evidence and detection target do not validate forecasting advantage. New entrypoint gives both methods the same observed history and future target. |
| High | Benchmark loads a checkpoint without proving its training partition; CV chooses a checkpoint using test-fold F1 | Held-out provenance is unproven. New trainer starts fresh, chooses weights with validation loss and records dataset hashes. It does not overwrite or activate the legacy checkpoint. |
| High | Lead time measured relative to sequence end / predicted peak, not annotated compromise | Claimed 60–150 seconds is not demonstrated. API measured lead time now null; predicted threshold-to-peak interval is separately named. |
| High | Failed PCAP parsing generated synthetic infiltration windows | Parse errors now propagate; unlabeled PCAP truth stays unknown, not benign. |
| High | Transformer attention endpoint creates random weights every request | Disabled with 503 until trained weights exist; random Transformer attention cannot explain LSTM decisions. |
| High | Mitigation bridge returned `ok: true` when backend failed | Now disabled by default and returns 502 on backend failure when enabled. |
| High | API telemetry history mixed every caller; PCAP used only final vector | Inference now uses request-local optional history; PCAP supplies its last 16 windows. Drift buffer is still process-wide and not tenant-safe. |
| High | Public API binding; unbounded forecast horizon/upload | Loopback is now default. Horizon bounded 1–32, vectors finite and normalized, capture upload capped at 10 MiB. Full authentication/quotas still needed. |
| High | CSV TTL variance derived from port entropy; PSH/URG used as fragmentation; FIN/RST as retransmissions; IAT unit/schema mismatch with PCAP | Remains a schema redesign blocker. CSV output marks proxy features explicitly. Do not interpret those dimensions as actual packet measurements. |
| Medium | PyTorch/JS/UI metrics were constants; JS forecast GET uses a constant state | API/JS metric values withdrawn; demo forecasts marked synthetic/unvalidated. HTML reports still contain legacy presentation claims. |
| Medium | HTTPS target passed to `http.request` | Transport selection now supports HTTPS and rejects other URL schemes. Syntax checked; TLS integration not exercised. |
| Medium | Missing multipart dependency | Added `python-multipart` and explicit Pydantic v2 requirement. Dependency installation not exercised here. |

## Actual supplied data

The two distinct CSV captures under `cicids2018_data` were streamed and counted:

| Filename | Parsed rows | Labels | Corrected windows |
|---|---:|---|---:|
| Friday-02-03-2018_Infiltration_REAL.csv | 199,999 | 162,906 Bot; 37,093 Benign | 3,136 |
| Thursday-01-03-2018_Infiltration.csv | 49,999 | 49,995 Benign; 4 repeated Label headers | 3,309 |

Neither file contains an Infiltration-labelled row. The filename is not reliable label evidence. Both headers lack source/destination IP pairs, TTL, actual fragmentation and retransmission fields. No raw PCAP is included in the archive. Root/subdirectory sample copies are not additional independent datasets. Full counts and SHA-256 hashes are in `ntro-world-model/dataset_audit.json`; hashes identify local bytes, not proof of official provenance.

Corrected future-only example construction yields 3,537 train / 1,220 validation / 1,243 test examples, with 535 / 472 / 978 positives. This is a strong time-dependent class shift. Examples within each split overlap and are correlated; do not treat them as independent observations for confidence intervals. Thresholding a window as malicious only when 35% of flows are malicious also hides small attacks; future work should define asset-level incident labels explicitly.

## GNN recommendation

Yes, a temporal graph extension is worth testing once endpoint-preserving telemetry and a trustworthy LSTM baseline exist. Do not add a GNN just for the acronym. Autoregression is a decoding procedure, not a competing model family, and can be used with either LSTM or graph encoders.

Proposed design:

1. Build one directed graph for each completed 10-second window. Nodes are hosts/services; edges are observed flows with protocol, direction, ports, byte/packet counts and timing. Preserve stable node identity over time. Never build graph edges using future windows.
2. Use a small GraphSAGE encoder for observed spatial relationships. Combine per-node embeddings with real flow/packet features.
3. Feed embeddings over time into a per-node LSTM. Decode future state/risk autoregressively. Future topology must be predicted or explicitly held fixed; it cannot be read from the test future.
4. Use independently supervised stage labels and report unknown where evidence is insufficient. Binary Bot/Benign labels cannot train Reconnaissance → Initial Access → Lateral Movement stage supervision.
5. Compare LR, persistence forecast, LSTM-only and GNN+LSTM under identical splits/cutoffs/targets. Keep the graph model only if it improves useful recall, forecast error or event lead time at acceptable false alarms and latency.

Implementation reference: https://pytorch-geometric.readthedocs.io/en/latest/generated/torch_geometric.nn.conv.SAGEConv.html . This revision deliberately does not ship a random/untrained GNN as an apparent product feature.

## New experimental retraining path

`forecast_dataset.py` builds 16 observed windows and 8 strictly future target windows, rejects capture boundaries/time gaps, and splits raw chronology before making sequences. `train_forecast_v2.py` trains the real PyTorch LSTM with autograd, compares an LR on flattened identical history, tunes both thresholds on validation, evaluates only on test, and compares future-state MSE against persistence. Risk means any attack-labelled window in the future horizon, not probability of compromise.

From the `ntro-world-model` directory, after installing requirements:

```bash
python train_forecast_v2.py --csv cicids2018_data/Thursday-01-03-2018_Infiltration.csv cicids2018_data/Friday-02-03-2018_Infiltration_REAL.csv --output forecast-v2
```

Outputs are a separate metadata-bearing checkpoint and metrics JSON. They are not drop-in replacements for the old API state dictionary: serving schema, checkpoint loader and risk semantics must be migrated together. This training path was syntax checked and its example builder regression-tested; training itself was NOT run because torch/sklearn were unavailable in this environment. No new F1 result is claimed.

It still inherits legacy feature proxies. An additional live-forecasting hazard is feature availability: completed-flow aggregates should enter at their availability/flow-end time, not retroactively at connection-start time. Correct this before claiming real-time early warning. Define timezone explicitly against capture metadata; the timestamp fix interprets the supplied naive clock uniformly as UTC for stable ordering, not proof that the original capture used UTC.

## Remaining work to reach a credible pilot

1. Replace proxy features with a versioned schema shared by CSV, PCAP and serving. Include missingness masks and measured units. Add bidirectional flow aggregation, real fragmentation and defensible retransmission tracking. Replay captured traffic in timestamp order. Treat missing windows explicitly.
2. Obtain attack timelines and a held-out day/campaign; establish earliest observable evidence and actual compromise/onset times. Measure precision/recall/FPR, PR-AUC, calibration, forecast error per horizon, false alerts per host-day, event lead time and missed events. Use event/day bootstrap intervals rather than per-overlapping-window independence.
3. Unify serving. Node currently runs a handwritten 16-hidden-unit JSON LSTM; Python uses a different 64-unit, two-layer checkpoint. The handwritten trainer uses approximate gate updates, not full BPTT. JS HTTP scenarios are not live network-flow forecasting. Prefer one versioned inference service, explicit model status and input provenance.
4. Fix explanations: Python GradientExplainer uses a random background and repeats a snapshot; it estimates attributions rather than exact Shapley values. Explain the actual ordered history and serving checkpoint against training-only background samples. JS `computeShapAttribution` is a feature-deviation heuristic. Label it accordingly. Documentation: https://shap.readthedocs.io/en/latest/generated/shap.GradientExplainer.html .
5. Add authenticated control plane, RBAC, strict proxy trust, origin/CSRF protections, upload and request quotas, bounded actor state, protected audit storage, signed/versioned model artifacts and tenant-separated history. Loopback alone is not authorization behind a local reverse proxy.
6. Put learned interventions in shadow mode first. Then require corroborating evidence, bounded TTL, allowlists, explicit scope, rollback and a kill switch. Demonstrate actual enforcement on owned lab assets; dashboard lockdown records are not proof of OS/network firewall installation.
7. Benchmark resource usage and latency under representative load. Bloom membership may be constant time but token scanning and retained JSON memory are not globally O(1) or 1 KiB. Saturation and poisoning need measurement. Regex/entropy tests do not demonstrate generic zero-day detection.
8. Pin tested dependencies, add installation/CI checks and update the deck/video with reproducible measurements. Keep all demo claims visibly distinct from measured results. Confirm the offline demo after dependency installation.

The official CIC description includes packet captures and system logs in addition to extracted flow features; use suitable original telemetry rather than fabricating missing packet attributes: https://www.unb.ca/cic/datasets/ids-2018.html .

## Verification performed

- Seven stdlib regression tests passed: hour/day preservation, malformed timestamp rejection, nonfinite parsing, no synthetic PCAP fallback, strictly future targets, capture/gap rejection and disjoint split windows.
- Five local HTTP checks passed: four source/memory/model/package URLs no longer expose project files, and forecast endpoint declares synthetic provenance. Test ran in a temporary isolated copy with a local stub upstream.
- All Python sources compiled; changed JS sources passed Node syntax checking; detection module loaded.
- Both distinct supplied CSV files counted and processed through corrected timestamp aggregation.
- Not run: full existing attack suites, PyTorch training/inference, SHAP/Scapy integration, TLS upstream integration, browser rendering, dependency audit, production load testing or external penetration tests. Missing ML dependencies prevent an honest model-accuracy validation in this session.

Tests from project root:

```bash
python ntro-world-model/tests/test_data_integrity.py
python tests/test_proxy_exposure.py
```

The proxy regression uses local port 18080. Run on an isolated development machine. Default listeners are now local-only; exposing either service requires proper authentication and deployment hardening first.
