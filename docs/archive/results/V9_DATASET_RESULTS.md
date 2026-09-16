# V9 — Additive public telemetry integration

CIC-IDS-2018 and all earlier results/checkpoints are preserved. This release adds
CICAPT-IIoT2024 network captures plus CTU-13 bidirectional flows. Experimental
multi-source weights are included; the default defence model is unchanged.

## Acquired and converted

| Source | Raw data acquired | Prepared representation | Label treatment |
|---|---|---|---|
| CICAPT-IIoT2024 phase 1 | 1,489,686,576 bytes; 12,103,705 packets | 5,752 one-minute host graphs; capacity 64, peak 26 hosts | Network risk/stages unknown |
| CICAPT-IIoT2024 phase 2 | 1,371,279,808 bytes; 9,571,528 packets | 4,323 one-minute host graphs; capacity 64, peak 18 hosts | Network risk/stages unknown |
| CTU-13 scenario 5 | 17,766,203 bytes | 31 one-minute service graphs | Botnet positive; Normal negative; Background unknown |
| CTU-13 scenario 7 | 15,630,512 bytes | 22 one-minute service graphs | Same conservative treatment |
| CICAPT provenance mirror | 418,855 process/artifact/edge rows across two phases | Separate candidate event timelines with source hashes | Not promoted to packet labels or verified supervised stages |

The complete two CICAPT network phases were processed, not a selected prefix.
Their `.pcap` filenames actually contain PCAPNG. A bounded parser preserves
interface timestamp resolution and offset, rejects malformed/out-of-order records,
and converts ten-minute chunks. First/final partial windows are excluded. No
snaplen-truncated records were found in these two captures. These are published
controlled-testbed captures, not observed enterprise production incidents.

CTU retains a separate service-graph track because its CSVs do not provide the
same packet features as CICAPT. Missing flags and backward packet counts are
explicitly documented; they are not reconstructed from labels. These two CTU
captures contain positive/unknown aggregate windows but no verified all-normal
windows, so they cannot establish an FPR by themselves. Their raw per-flow labels
are retained. CTU was imported but not included in the host-model fit.

## Executed comparison — no improvement claim

Fixed seeds 42, 43, 44; 12 epochs; residual decoder; 8 observed one-minute windows;
4 future windows; stride 16. Logistic regression, LSTM and GNN+LSTM checkpoints
are included for each run. Logistic regression predicts risk, not future states;
CICAPT risk labels remain unverified, so its test F1/FPR/recall are unavailable.

| Development sources | State model | Held-out state MSE, mean ± sample SD |
|---|---|---|
| ids_only | lstm | 0.010534 ± 0.000658 |
| ids_only | gnn_lstm | 0.010713 ± 0.000664 |
| ids_plus_cicapt | lstm | 0.010855 ± 0.000548 |
| ids_plus_cicapt | gnn_lstm | 0.011589 ± 0.000616 |
| — | Persistence | 0.009824 |

Lower is better. All runs evaluate the same 270 examples from CICAPT phase 2.
Adding phase 1 did **not** improve this experiment. None of these averaged learned
state models beats persistence. Do not market this as a forecasting accuracy
improvement or a successful pilot gate. Per-run block-bootstrap intervals and
per-feature errors are in `datasets/multisource/benchmark_summary.json` and the
individual metrics reports. Seed variation is not replication across independent
attack campaigns. Test results were not used to search hyperparameters.

Development = three existing IDS2018 capture days, with/without CICAPT phase 1.
Within each development capture: first 70% training, later validation after a
12-window embargo. CICAPT phase 2 is entirely held out. No example crosses a
capture, partition boundary or missing time bucket. Feature scaling uses the
existing fixed physical/log transforms; risk class weighting uses training only;
calibration uses validation only and remains unsupported when samples are scarce.

## Annotation audit and remaining gates

The provenance mirror phase 1 contains only zero-labelled rows. Phase 2 contains
publisher stage strings including initialAccess, collection, exfiltration, CandC,
discovery, persistence, credentialAccess, lateralMovement and defenceEvasion.
These are candidate process/artifact events. We have not verified their clock
alignment, completeness or labels against the original Caldera Attack_info.csv.
First-seen process timestamps are not verified compromise timestamps. Discovery
must not silently become pre-compromise Reconnaissance. The exporter preserves
these distinctions and does not fabricate negatives.

The official CICAPT download path presented registration and a server error;
public mirrors were used and are named in the catalogue. The packet mirror's MIT
claim does not independently establish the original dataset's commercial terms.
Dataset research access and product redistribution rights are separate checks.

Thus: cross-family FPR/recall, pre-compromise warning lead time, and supervised
network-stage accuracy remain unproven by this release. Candidate checkpoints
remain research-only; automatic containment is not approved. Adding data did not
fix these gates. Next useful work is verified event alignment and a domain-aware
training experiment with another untouched test capture, not relabelling this
already-evaluated phase as a fresh holdout.

## Reproduce

Run from the KrishnaDefence project root:

```bash
python -m garuda_v3.public_data_fetch --extract
python -m garuda_v3.multisource pcapng datasets/multisource/raw/1stPhase-timed-Merged.pcap --output datasets/multisource/graphs/cicapt_phase1.npz --campaign cicapt_phase1
python -m garuda_v3.multisource pcapng datasets/multisource/raw/2ndPhase-timed-MergedV2.pcap --output datasets/multisource/graphs/cicapt_phase2.npz --campaign cicapt_phase2
python -m garuda_v3.multisource ctu datasets/multisource/raw/capture20110815-2.binetflow --output datasets/multisource/graphs/ctu_scenario5.npz --campaign ctu_scenario5
python -m garuda_v3.multisource ctu datasets/multisource/raw/capture20110816-2.binetflow --output datasets/multisource/graphs/ctu_scenario7.npz --campaign ctu_scenario7
python -m garuda_v3.multisource_benchmark
python -m unittest discover -s garuda_v3/tests
```

Prepared graphs, all six fitted experiment runs, source catalogue, candidate
annotation audits and logs are in the main project ZIP. Raw CICAPT captures and
other newly acquired telemetry are in two additional ZIPs; extract them beside
the main ZIP so their KrishnaDefence directories merge. The downloader is pinned
to exact versions, byte lengths and SHA-256 hashes; changed public content fails
closed. Existing benchmark outputs are reused, never overwritten. To refit,
archive the experiment output directory first.

## Sources

- [CICAPT-IIoT2024 publisher](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html)
- [CICAPT raw network mirror, version 1](https://www.kaggle.com/datasets/jvn3jean/cicapt-iiot2024)
- [CICAPT provenance mirror, version 1](https://www.kaggle.com/datasets/trungtrch/cicapt-iiot-dataset)
- [CTU-13 publisher and citation](https://www.stratosphereips.org/datasets-ctu13)

Exact download URLs and member hashes are in `datasets/multisource/catalogue.json`.

## Verification

59 Python tests passed, including PCAPNG timestamp resolution, malformed/out-of-order rejection, chunk boundaries, CTU unknown-label preservation and completed-flow availability timing. Integration processed both complete CICAPT captures and both downloaded CTU files.
