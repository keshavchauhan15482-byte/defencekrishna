# Forecast evidence contracts: scope and remaining data gates

This change repairs code/reporting, not historical model outcomes. Old runs and
exposed holdouts remain unchanged. No new universal generalisation or five-stage
forecasting PASS follows from regression tests.

## Complete matched baseline

`GET /bridge/evidence` exposes precision, recall, F1 and FPR from the authoritative
V88 report with its SHA256. The console keeps this two-episode UNSW comparison
separate from the internal-holdout table. No synthetic aggregate blends it with
CICAPT state MSE. This endpoint does not reproduce or authenticate the experiment.

## Ground truth to training targets

The existing path is `raw capture -> graph -> annotations.annotate -> y/stage_y
-> chronological future windows -> training`. `annotations.py` requires matching
capture identity and reviewed half-open intervals. A window crossing an annotation
boundary stays unknown. Stage absence is never inferred from a missing annotation.
Annotations do not enter network features. Each annotated graph now records per-stage
known/positive support and unknown risk windows in `metadata.timeline_supervision`.

Use the existing preparation CLI with a reviewed publisher-derived interval sidecar:

```sh
python -m garuda_v3.annotations capture.pcap --kind pcap --mode host \
  --annotations reviewed_intervals.json --output new_labelled_graph.npz
```

The sidecar must include `source_sha256`, `campaign_id`, `intervals` with explicit
UTC epoch `start/end`, binary `label`, evidence references and optional exact
five-stage labels. Source annotations must supply defensible intervals; a point
attack-step timestamp alone must NOT be stretched into an invented stage interval.
The existing 34-feature coupled-head path requires its own PS-complete service graph
contract; do not relabel a 21-feature graph as that input.

Validator repairs reject NaN/infinite timestamps, non-hex source hashes,
attack/benign contradictions and string-valued compromise flags. Adjacent reviewed
benign intervals now provide continuous coverage without requiring one oversized
interval. Graph timestamp ordering, label shape and binary-stage values are checked.
Hashes bind bytes; publisher authenticity still requires review of original sources.

## MITRE accounting

`evidence_contracts.five_stage_report` returns five per-stage precision/recall/F1
rows, support, confusion matrix with abstention column, coverage and an explicit
all-five support gate. Missing classes cannot be certified by averaging only the
classes that exist. Abstained attacks count as misses. This is classification
accounting; apply it to separately evaluated horizon-aligned targets for a forecasting
claim. Threshold/support policies must be frozen before final evaluation.

The committed V124 record-classifier result remains FAIL. Its test supports are
1058 Recon, 8 Initial Access, 6 Lateral Movement, 4 C2 and 5 Exfiltration.
Initial Access recall is 37.5% in that experiment. Other replication experiments
must retain their own scope. Rebalancing cannot create independent rare-stage cases.

## Unseen-domain evaluation

`evidence_contracts.audit_holdout` checks declared campaign/source disjointness,
previously exposed source identities, train-only normalization/class balancing and
validation-only calibration/threshold sources. It is a declaration consistency
check, not proof of publisher authenticity or model quality. The matched metric
function requires one common cohort and input-feature hash for every model.
Zero negative support returns null FPR, never a perfect zero. No function here
changes thresholds based on final-test outcomes or authorizes containment.

The actual `coupled_heads` trainer now uses the corrected accounting, rejects
declared exposed final campaigns/sources, and reports all five stages separately
for each forecast horizon. Its release gate requires support/recall at each horizon,
not pooled counts inflated by combining four correlated horizons.

Still required for a new model-improvement claim: independently labelled rare-stage
campaigns, sufficient matched benign traffic, untouched final source reservation,
training-only fitting, frozen multi-seed evaluation and honest per-family results.
Existing exposed IoT-23/RT-IoT2022/ToN-IoT results cannot become fresh holdouts.

## Explainability

Runtime gradient-times-input and the separate `shap_explainability.py` Kernel SHAP
CLI are distinct methods. SHAP is optional and is not automatically executed by the
default runtime. Neither method establishes causality. Do not label a gradient
attribution as SHAP merely because the interface could support SHAP later.

## Local verification

67 focused Python regression tests passed, covering the new contracts, existing
SHAP coalitions, annotation/training/inference smoke, dynamics freezing, campaign
splits, timeline parsing, calibration and statistics. Python compile-all and JS
syntax checks passed. These are engineering checks, not a new model benchmark.
The Node UI regressions exercise complete metrics, offline failure and partial
response handling. Full repository CI and browser visual QA are separate checks.
