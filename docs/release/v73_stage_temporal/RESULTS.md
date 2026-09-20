# V73 Five-Stage Lifecycle Proxy — Temporal Block Holdout

Authoritative GitHub Actions run: `35525990295` (`V73 stage-stratified temporal benchmark`). Status: **SUCCESS**.

## Protocol

X-IIoTID lifecycle stages are globally campaign-ordered, so one global chronological cutoff cannot place all five requested stages on both sides of train/test. V73 therefore uses a predeclared **per-stage temporal block holdout**:

- earliest 55% of each stage block: training
- next 15%: validation
- 12 sequence-index embargo between adjacent blocks
- latest remaining block: test
- split selection uses no model metric
- train / validation / test sequences are disjoint
- within every stage, train timestamps precede validation timestamps and validation timestamps precede test timestamps
- this is **not** a globally chronological future-campaign benchmark

Stage mapping is explicit:

- Reconnaissance → Reconnaissance
- Exploitation → **Initial Access proxy** (not exact MITRE Initial Access truth)
- Lateral Movement → Lateral Movement
- C&C → Command & Control
- Exfiltration → Exfiltration

The stage mapper is trained on future-state representations from the training blocks and is evaluated on Garuda forecast states in the held-out blocks. Attack labels are not world-model inputs.

## Support

| Stage | Train | Validation | Test |
|---|---:|---:|---:|
| Reconnaissance | 200 | 54 | 86 |
| Initial Access proxy | 106 | 28 | 35 |
| Lateral Movement | 878 | 239 | 457 |
| Command & Control | 102 | 27 | 33 |
| Exfiltration | 259 | 70 | 118 |
| **Total test** |  |  | **729** |

## Three-seed result

Seeds 42/43/44 produced the same held-out stage metric:

- Accuracy: **87.7915%**
- Macro F1: **68.3203%**
- Macro recall: **79.8687%**
- Macro precision: **64.6423%**
- Macro-F1 SD across seeds: **0.0 pp**
- All five stages are present in the test set.
- World-model validation persistence gate: PASS for all three seeds.

However, persistence-state stage mapping produced the **same 68.3203% macro F1**, so this protocol does **not** demonstrate a stage-mapping advantage from forecast states.

## Exact per-stage result

The confusion matrix is identical for all three seeds.

| True stage | Test support | Correct | Recall | Main error |
|---|---:|---:|---:|---|
| Reconnaissance | 86 | 0 | **0.0000%** | all 86 predicted Initial Access proxy |
| Initial Access proxy | 35 | 35 | **100.0000%** | precision only 28.9256% because Recon maps here |
| Lateral Movement | 457 | 454 | **99.3435%** | 1→Recon, 2→C&C |
| Command & Control | 33 | 33 | **100.0000%** | 2 Lateral false positives reduce precision to 94.2857% |
| Exfiltration | 118 | 118 | **100.0000%** | none in this holdout |

## Release decision

This result is useful supervised lifecycle-stage **development evidence**, but it is **not release-quality five-stage MITRE evidence** because:

1. Reconnaissance recall is 0%.
2. `Exploitation` is only an Initial Access proxy.
3. The split is temporal within stage, not globally chronological across campaigns.
4. Forecast-state stage F1 does not beat persistence-state stage F1 in this protocol.
5. CICAPT publisher-validated network-stage labels remain too sparse for a trustworthy five-class MITRE F1.

The result is intentionally preserved rather than replaced by a higher-looking accuracy number. The next stage-model iteration must improve Reconnaissance/Initial-Access separation using development/validation data only, followed by a separately frozen fresh holdout.
