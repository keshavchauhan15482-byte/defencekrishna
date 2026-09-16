# Historical evidence archive

This directory preserves superseded, exploratory, failed, or development-only reports for reproducibility and auditability.

Files here are **not current release claims**. They are intentionally retained rather than deleted so earlier failures, dataset limitations, calibration problems, and architecture comparisons remain inspectable.

For current judge-facing evidence, start at [`../../RELEASE_EVIDENCE.md`](../../RELEASE_EVIDENCE.md) and [`../release/`](../release/).

The pre-cleanup repository-wide SHA-256 path manifest is preserved under [`provenance/`](provenance/). It describes the old layout and is historical provenance, not a current-tree integrity manifest.

Important interpretation rules:

- archived host/service-graph failures do not invalidate the separately frozen V48 X-IIoTID reserve-family benchmark;
- archived scores must not be presented as current production or SIH release metrics;
- a failed or superseded experiment remains part of the research record;
- no archived result should be relabelled as a fresh holdout after inspection.
