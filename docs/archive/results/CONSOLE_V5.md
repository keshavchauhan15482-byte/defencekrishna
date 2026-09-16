# Console 5: evidence and protection rehearsal

The hosted console now has a real authenticated HTTP protection lab. It uses durable per-user policies and a decision ledger, HMAC-authenticated policy envelopes, expiry, bounded requests and scoped test identities. The hosted model view still shows recorded forecasts. Live NumPy inference and CSV/PCAP ingestion remain in this offline project.

Hosted console: https://krishna-defence-console-keshav.keshavchauhan1254.chatgpt.site

## Changes

- Conservative observed-behaviour stage hints, explicitly heuristic, unvalidated and not ML-trained. Internal scanning candidates map to Discovery/T1046; external scanning candidates map to Reconnaissance/T1595. A port or risk score alone never establishes a tactic. Remote-service activity receives a useful investigation label without inventing Initial Access or Lateral Movement.
- Matched three-seed model comparison, including mean and sample standard deviation for every model. Seeds 42, 7 and 19 use the same reused holdout. GNN mean F1 96.04%, LSTM 94.24%, logistic regression 91.63%. These are initialization repeats, not independent datasets.
- A 51-host original-PCAP topology selected from a QC-valid window. No nodes are invented. The service checkpoint does not forecast this host graph. Select Recorded alert separately for the service-model trajectory.
- Hosted WebGL network and defence-architecture modes, accessible node selection, perspective fallback, observed activity and degree charts, feature contributions and model evidence.
- Cross-day roadmap both on the site and as `sih_submission/CrossDay_Pilot_Roadmap.pptx`. Replace the old roadmap slide when keeping a five-slide submission.

## Run the local project

Follow README.md and run `python3 -m garuda_v3.server`. Connect using your locally generated access token. Choose Explore host topology for actual endpoints, or Run alert replay for a trained service-model forecast. Local metrics now show the matched three-seed summary, and stage hints remain separate from supervised predictions.

The premium hosted interface and its Worker source are maintained in the Site's source repository. This ZIP contains the offline Python project, trained artifacts, datasets and updated evidence documents.

## Rehearsal on the hosted site

Open Protection lab and select Run full rehearsal. It sends actual HTTP requests to an isolated protected handler. Expected checks: benign 200; SQLi, script, traversal and command patterns 403; manual signed policy blocks the selected test identity before the handler; the other identity remains 200; emergency revoke restores 200. Check the decision ledger for each result. Manual policy and emergency revoke can also be exercised individually.

Documentation-range addresses are test identities, not actual visitors' IP addresses. Known-pattern probes contain inert strings that never execute. Unmatched traffic is marked for review and may reach the handler; it is not claimed to be a detected or blocked zero-day. Signing authenticates policies, not data encryption. This does not protect an external enterprise network.

## Verification on 2026-09-12

40 Python tests pass. Six server tests cover authentication/origin/scope, signature enforcement and tampering, expiry, user isolation, emergency revoke after quota, bounded bodies and actual HTTP routing. The supervised browser preview passed all eight rehearsal checks and manual publish/block/revoke/recovery. Desktop overflow was absent. Browser WebGL was disabled, so hardware rendering and mobile layout could not be verified there; the fallback architecture view was inspected. Preview testing uses the same Worker handler with a local SQLite adapter, not the deployed D1 instance.

## Remaining release gates

Cross-day generalization is NOT fixed by this console work: the host checkpoint's existing test still has 100% false-positive rate, and state forecasting does not beat persistence. A fresh untouched capture-day/attack-family holdout, calibration, more clean-history positives, verified lead time, supervised stage annotations, real host attribution, shadow-mode deployment and independent security review remain necessary. Proposed roadmap thresholds are goals, not achieved scores. This release is an improved research prototype and isolated control lab, not a market-ready autonomous defence product.

MITRE references: https://attack.mitre.org/techniques/T1595/ and https://attack.mitre.org/techniques/T1046/
