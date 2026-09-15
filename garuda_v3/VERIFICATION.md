# Verification record - 11 September 2026

Latest PCAP update output: `IDS2018_VERIFICATION.txt`. Includes actual capture CRC/hash checks, observed-graph conversion, host-model training and documented failed held-out evaluation. Previous verification statements below predate this experiment.

Environment: Python 3.12.14, NumPy 2.3.5, scikit-learn 1.8.0, Node 24.19.0, CPU. Network package installation was unavailable; training and inference ran with installed NumPy/scikit-learn and the new tested reverse-mode engine.

Current residual-update verification:

- 28 unit/integration tests passed, including the earlier 21 checks plus seven tests for residual gradients and persistence initialization, unknown-stage masking, annotation source binding/boundaries, incident misses and timing, campaign separation, alert calibration, and end-to-end synthetic host/packet-stage training and serving. Synthetic fixtures validate software only.
- Actual residual retraining completed for seeds 42, 7 and 19 on the supplied service CSV graphs. Metrics, paired state diagnostics and checkpoint hashes are retained in `artifacts/residual_*`.
- Default authenticated demo/API checks now run against the residual seed-42 checkpoint.
- Dashboard JavaScript syntax checked. No browser tooling was available for interactive visual QA.
- Current raw output: `RESIDUAL_VERIFICATION.txt`. The older output remains historical evidence.

Completed in the preceding revision:

- 21 v3 unit/integration tests, including numerical finite-difference gradients through GNN and LSTM, optimizer learning, node permutation invariance, graph-edge sensitivity, checkpoint roundtrip/integrity, data split isolation, real packet decoding, API authorization/schema checks, signed policy blocking and revocation.
- 7 earlier data-integrity regression tests.
- 5 earlier local HTTP source-exposure/provenance checks.
- Primary training and two additional seeds, with full metrics, predictions, checkpoints and metadata retained.
- Changed JavaScript syntax and Python compilation.
- Five-slide PPTX structural/layout validation and individual rendered-slide review.
- Two-page architecture PDF rendered and reviewed.

Previous-revision automated output: `VERIFICATION.txt`. Reproduce commands from the root README.

Not completed: browser interaction/rendering of the offline dashboard (browser tooling unavailable), cross-platform installation, real-data packet/host checkpoint training, independently labelled attack-stage validation, pre-compromise timing evaluation, independent penetration testing, production load/availability certification, and external dataset provenance verification. A two-minute recording script is included, not a finished video. No repository or site was published.

Do not interpret passing tests as proof that no vulnerabilities remain. Legacy modules were not exhaustively reviewed or retested. The entrypoint and submission documents explicitly supersede their historical claims.
