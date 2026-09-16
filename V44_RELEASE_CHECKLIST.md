# V44 release checklist

A V44 model may replace the live Garuda checkpoint only when every item is true:

- [ ] The strict network-only feature audit passes on the actual source CSV/PCAP.
- [ ] The selected features are mapped to the live 10-second graph schema.
- [ ] Normalization and imputation are fitted on training data only.
- [ ] Calibration and policy blocks each contain independent benign and attack examples.
- [ ] A newly reserved day/device/attack-family holdout is untouched during model selection.
- [ ] FPR is at most 1% and recall at least 80% per held-out family.
- [ ] At least five independently evaluable events exist per family.
- [ ] At least one verified clean-history future-positive incident has an authoritative onset/compromise timestamp.
- [ ] Warning lead time is measured against that timestamp.
- [ ] MITRE stages are supervised from original timeline evidence; unsupported stages say “Insufficient evidence”.
- [ ] Unknown-lane autonomous containment remains disabled unless all preceding evidence passes.
- [ ] Dataset hashes, split manifest, model hash, metrics, and CI artifact digest are committed.

A failed checkbox is a release blocker, not a reason to lower the threshold or rename a diagnostic result.
