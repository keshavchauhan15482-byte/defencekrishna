# Audit runtime fixes

This change fixes three operational defects and adds strict experimental paths for the two evidence-dependent gaps. It does not claim verified advance warning or a newly validated future-stage model.

## Changes

- One loopback listener/process on **8090** serves the original charcoal/orange `console.html`, model inference and the same-process lab bridge. `start_local.py`, `start_main_console.py`, Windows/macOS launchers and legacy console module commands converge on this runtime.
- Browser bearer credentials are not exposed. Host/Origin checks, request bounds, inference serialization and quotas apply. The console uses nonce-protected inline scripts; arbitrary policy changes still require operator bearer authorization.
- The missing evaluator claim boundaries are restored. The asset contract accepts the script's actual hardened routing table. CI now runs **pytest**, including function tests previously missed by unittest discovery.
- The March 2 raw PCAP is replaced by a fresh official S3 ZIP-member extraction with exact size, CRC and the already recorded expected SHA-256. The previous bundled file hash was `7f4e6a44d7321f4d36699528a3835af320f613d1314fbd6188bc7c37038d8a2d`; restored expected hash is `56fc8375d9104615ec08952bf811cc17e0579af5d2fc98e54dea669cc9d5d58e`.
- Packet preparation preserves original recordings, copies complete records, excludes the entire terminal 10s bucket and entire windows containing malformed packet headers. It records discarded bytes/windows and never creates attack labels. Strict runtime parsers are unchanged.
- PCAP uploads up to 72 MiB show the latest 34-feature state trajectory independently of legacy risk availability. A model/parser failure never becomes a clean or benign verdict.

## Run

```bash
python -m garuda_v3.pcap_packaging --output-dir datasets/ids2018/prepared
python start_local.py
```

Open `http://127.0.0.1:8090/console.html`. Upload **prepared** captures, not the known malformed originals. Preparation is immutable: use a new output directory on a repeat run. Outputs are derivatives, not publisher-complete recordings. Removed windows create gaps; no imputation joins them.

`pcap_packaging_audit.json` records all four derivations. `pcap_live_smoke.json` records finite +10/+20/+30/+40s state outputs for all four. These are ingestion/inference checks, **not attack recall/FPR measurements**.

## Coupled future-head experiment

`python -m garuda_v3.coupled_heads` trains future risk and exact five-stage heads on the **same frozen V123 GraphSAGE/LSTM backbone**, rather than reusing a separate network-record classifier. State parameters must remain byte-identical. Unknown targets remain -1; ambiguous/overlapping tactics cannot become a fabricated single stage.

Prepare reviewed packet graphs with the existing extractor:

```bash
python -m garuda_v3.ps_complete prepared.pcap --output reviewed-windows.npz --campaign CAMPAIGN --mode service --max-nodes 32 --annotations reviewed-intervals.json
python -m garuda_v3.coupled_heads --prepare-window-graph reviewed-windows.npz --output sequences.npz
python -m garuda_v3.coupled_heads --manifest reviewed-split.json --output new-head-experiment --seeds 42 43 44
```

The manifest has `train`, `validation`, `test` arrays. Each entry contains `path`, `sha256`, `campaign_id`, `family`, `labels_reviewed: true`, `raw_source_path`, `raw_source_sha256`, `annotation_path`, `annotation_sha256`. Include `backbone_development_source_sha256` with the actual pinned V116 Phase-1 and Phase-2 hashes. Paths resolve relative to the manifest. Raw files and annotation files are hashed independently.

Every input NPZ contains 80s graph histories, four future risk targets and four exact stage targets. Features and campaign identity must match metadata. Train/validation/test campaigns and raw sources are disjoint, and backbone-consumed sources cannot be final test. There is no aggressive class balancing. Checkpoint choice and alert thresholds use validation only. Reports retain every seed, family and horizon; the strict final gates require recall >=80%, FPR <=1%, minimum positive/negative support, and sufficient stage support. No best seed is selected for promotion.

Optional research integration:

```bash
GARUDA_COUPLED_HEAD_EXPERIMENT=/absolute/path/new-head-experiment python start_local.py
```

This exposes candidate future scores/stages from the same backbone in a **separate shadow-only field**. It verifies checkpoint hashes and unchanged state weights. Scores are explicitly uncalibrated, unsupported stages abstain, and it cannot authorize containment. The certified state/risk bundles are not overwritten.

The current repo's labelled window graphs have **21 features and no `stage_y`**; they cannot satisfy this 34-feature future-head contract. The existing V125 record-classifier results are not upgraded or rewritten.

## Objective pre-compromise evaluation

```bash
python -m garuda_v3.campaign_evidence --manifest independently-reviewed-campaigns.json --output new-objective-report
```

The manifest contains V107 `provenance` and a `campaigns` array. Each campaign contains `campaign_id`, `graph_path`, `graph_sha256`, `objective_events_path`, `objective_events_sha256`. Objective-event JSON is a list of independently sourced V107 successful-compromise events, not Attack_info attack steps. Window graph metadata must identify its campaign and explicitly set `risk_labels_reviewed: true` after review.

The evaluator uses observed history only, excludes unknown/non-clean histories, accounts for every supplied campaign including misses, selects the first objective success event and delegates hash-pinned pair verification to V110/V107. It reports retrospective event recall and lead time. Retrospective replay is **not a live warning claim**.

No available same-campaign objective successful-compromise/model-warning pair was found in the current release evidence. Therefore this remains **insufficient objective evidence**, not PASS. An attack-step CSV cannot close that gap.

## Verification scope

Linux CPU, loopback HTTP lab, automated regression, official-data hash/CRC checks and real packet ingestion. No public targets were attacked, and no enterprise pilot, independent penetration test or Windows execution is claimed. Historical forecast/stage benchmark scores remain unchanged.
