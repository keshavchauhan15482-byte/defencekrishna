# V52 — CICAPT timeline / lead-time evidence

V48 establishes controlled unseen-family generalisation on frozen reserve families. V52 targets the next missing SIH evidence: whether a frozen Garuda warning occurs **before an independently recorded attack step**.

## Why CICAPT-IIoT2024

The CICAPT-IIoT2024 experiment emulates an APT campaign with MITRE Caldera. The publisher describes a normal first phase and an attack second phase, with attack execution spread over time rather than collapsed into one static label. The publisher also describes supplementary attack information extracted from Caldera reports, including attack time and attack category. That makes the dataset suitable for a provenance-first temporal warning audit if the original annotation file can be recovered and aligned without guessing.

The repository already contains hash-pinned public mirrors for network/provenance data and a **candidate** Phase-2 timeline derived from provenance labels. That candidate timeline remains comparison evidence only. It is not upgraded to verified ground truth unless it matches an independently sourced `Attack_info.csv` / Caldera annotation.

## Stage 1: source provenance audit

The V52 workflow first downloads the small hash-pinned CICAPT provenance mirror from `datasets/multisource/catalogue.json` and inspects the ZIP without executing any archive content.

If exactly one `Attack_info.csv` exists, V52:

- extracts it to a basename-only path;
- records archive/member SHA-256 and byte size;
- resolves event-time and attack-identity columns;
- refuses row-order time reconstruction;
- refuses time-of-day timestamps without an explicit independently justified date;
- compares source events with the existing candidate provenance timeline within a declared tolerance;
- records whether any explicit compromise timestamp field actually exists.

If the file is missing, duplicated, structurally ambiguous or lacks absolute timestamps, V52 writes the blocker to an immutable evidence artifact. It does not synthesize missing dates or convert provenance labels into stronger truth.

## Executed source audit

GitHub Actions run `35110038265` executed the V52 audit end to end after all six V52 unit tests passed.

The hash-pinned provenance archive was confirmed as:

- filename: `cicapt-provenance-mirror.zip`;
- size: 6,525,709 bytes;
- SHA-256: `ffcbbd92541eeb3cdcebe53380d202bb2a453907585f80edb70952f1b40040be`;
- archive members: `Phase1_Provenance.csv`, `Phase2_Provenance.csv` only.

Therefore the pinned archive does **not** contain `Attack_info.csv`. V52 also performed narrow single-file probes against the known public Kaggle mirrors and plausible supplementary paths; none exposed a recoverable `Attack_info.csv` through the public API in this run. No large raw dataset was downloaded for this probe.

Evidence artifact: `v52-cicapt-timeline-source-audit`, artifact ID `10451842732`, ZIP digest `sha256:54f09dfc19b3bbd30dd423957a9288d59a524193d06f09f85aa246a251fe5ee8`.

Current fail-closed status:

- `source_ready = false`;
- `timeline_audit_completed = false`;
- `verified_compromise_lead_time_supported = false`.

This is a **data provenance blocker, not a model pass/fail**. The publisher documents that the supplementary dataset contains `Attack_info.csv`, but the currently reproducible pinned/public mirrors available to CI do not expose that file. The existing provenance-derived Phase-2 candidate timeline remains development/comparison evidence only.

## Stage 2: frozen alert lead-time audit

`garuda_v3.v52_cicapt_timeline leadtime` accepts only an explicit frozen alert-decision stream with timestamps. For each source event it measures whether an alert happened strictly before the event within a declared lookback window.

The report includes:

- first warning before each event;
- lead seconds to attack-step onset;
- timeline-clean-history support;
- warning hits/misses and event recall;
- the exact hashes of the timeline audit and alert stream.

An alert at or after the event never counts as an early warning.

## Claim boundary

Unless an independently sourced annotation contains a specific successful-compromise timestamp, V52 reports **attack-step onset lead time**, not compromise lead time. A Caldera command marked successful is not automatically equivalent to successful host/network compromise.

V52 does not by itself establish production zero-day detection, successful compromise prevention, autonomous containment approval or enterprise deployment readiness.

## Release path

A strong final pre-compromise result still requires a frozen model/scorer, clean pre-event traffic, independently verified incident outcome/timestamps and a campaign that was not used to tune the alert. V52 builds the evidence machinery and source audit needed to make that later claim without leakage or timestamp invention.

The fastest way to unblock the CICAPT route is to obtain the publisher-provided supplementary `Attack_info.csv` from the official CIC dataset download and run it through the already-frozen V52 audit. Until that exact source is available, no CICAPT pre-compromise/compromise lead-time claim will be promoted.
