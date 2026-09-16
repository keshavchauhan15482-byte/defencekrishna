# V46 PS-complete three-seed diagnostic results

This report records the first executed V46 run after expanding the network-state schema to cover the remaining SIH flow/packet attributes. It is deliberately a **development diagnostic**, not release-grade forecasting evidence.

## Evidence scope

- Window: **10 seconds**
- History: **8 windows / 80 seconds**
- Forecast horizon: **4 windows / 10, 20, 30, 40 seconds**
- Features: **34 flow + packet telemetry dimensions**
- Models: logistic regression, residual LSTM, residual GNN+LSTM
- Seeds: **42, 43, 44**; every seed reported, no best-seed promotion
- Train campaign: `Thursday-22-02-2018` (web)
- Validation campaign: `Friday-23-02-2018` (web)
- Test campaigns: `Thursday-01-03-2018` (infiltration) + `Friday-02-03-2018` (botnet)
- Evaluation scope: `development_reused_holdout`
- Labels: schedule-assisted weak IDS2018 labels; **not verified compromise/stage truth**
- Release evidence eligible: **false**

Sequence counts after continuity/history/horizon rules: train **175**, validation **201**, test **171**. Known aggregate risk test support is 128 examples: 71 positive and 57 negative.

## Packet-integrity preparation

The strict PCAP decoder exposed incomplete packet evidence in the committed victim-capture members. V46 does not impute missing bytes. An audited derivative copies complete records byte-for-byte and excludes the entire 10-second state if any packet in that state is structurally incomplete.

| Capture | Prepared windows | Excluded incomplete-evidence windows | Complete records retained |
|---|---:|---:|---:|
| Thursday-22-02-2018 | 2,663 | 1 | 47,712 |
| Friday-23-02-2018 | 2,713 | 1 | 55,098 |
| Thursday-01-03-2018 | 193 | 0 | 121,383 |
| Friday-02-03-2018 | 720 | 221 | 73,262 |

The large Friday-02 exclusion is itself useful provenance evidence: this committed capture contains many records that the strict IPv4 decoder cannot treat as complete packet observations. Those windows are not silently repaired or counted as clean states.

## State forecasting

Validation selects the state checkpoint without test labels. Every seed beats validation persistence, so the risk head is allowed to train. However, on the reused cross-family test campaigns, both learned world models are worse than persistence.

| Model | Validation MSE improvement vs persistence | Test state MSE, mean ± SD | Test persistence MSE | Test result |
|---|---:|---:|---:|---|
| LSTM | **36.95% mean** | **0.022300 ± 0.002294** | **0.018294** | worse than persistence by 21.90% |
| GNN+LSTM | **34.17% mean** | **0.023256 ± 0.002802** | **0.018294** | worse than persistence by 27.12% |

Interpretation: the expanded state model learns the web-development dynamics but does not transfer its learned residual dynamics reliably to these botnet/infiltration captures. This is a domain/campaign-generalisation failure, not a reason to tune on the exposed test set.

## Future-risk diagnostic

The validation threshold is selected under the requested 1% FPR budget. Test behavior shows why the release gate remains necessary.

| Model | F1 mean ± SD | Precision mean ± SD | Recall mean ± SD | FPR mean ± SD |
|---|---:|---:|---:|---:|
| Logistic regression | 69.07% ± 0.00 | 54.47% ± 0.00 | 94.37% ± 0.00 | **98.25% ± 0.00** |
| LSTM | 24.30% ± 39.74 | 35.28% ± 30.69 | 31.92% ± 54.08 | **31.58% ± 53.18** |
| GNN+LSTM | 8.04% ± 11.67 | 34.19% ± 34.62 | 4.69% ± 6.95 | **3.51% ± 3.51** |

No model passes the requested **FPR <= 1% and recall >= 80%** cross-family gate. GNN+LSTM reduces false alerts relative to LR/LSTM in this diagnostic, but recall collapses. LSTM is highly seed-sensitive: one seed behaves like a high-recall/high-FPR classifier while another nearly abstains.

Per-family evidence is also insufficient:

- Botnet has both positive and negative examples, but no LSTM/GNN seed passes both FPR and recall requirements.
- Infiltration has positive examples but **zero known benign negatives** under this capture/label contract, so it cannot establish an infiltration FPR.
- Clean-history test support has 57 known benign examples and **zero clean-history future-positive examples**. Therefore this run cannot measure advance warning lead time.

## MITRE and pre-compromise status

- Supervised stage rows: **none**; no stage accuracy/F1 is claimed.
- Verified compromise lead time: **unavailable**; no verified compromise timestamps were supplied.
- Automatic containment approval: **false**.

The five-stage training path exists, but it remains disabled until reviewed `stage_y` supervision exists for Reconnaissance, Initial Access, Lateral Movement, Command & Control and Exfiltration.

## What this result changes

V46 closes a **problem-statement feature-contract gap** and makes the next failure measurable. The next bottleneck is not adding a Transformer or more epochs. It is obtaining independent campaigns and verified timelines, then improving domain transfer using development data only.

Do **not** tune architecture, feature weights or thresholds against the exposed V46 test metrics and then relabel the same campaigns as a fresh holdout. A new predeclared final campaign is required for a release claim.

## Reproduction evidence

GitHub Actions workflow `V46 PS-complete diagnostic`, run `35087082701`, completed successfully. Its artifact includes all three per-seed `metrics.json` reports, the no-cherry-pick summary and four packet-integrity audits. Full Krishna regression CI also passed on the same PR head.
