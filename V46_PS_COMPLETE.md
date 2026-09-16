# V46 PS-complete forecasting path

V46 is an **additive** SIH problem-statement coverage path. It does not replace, rewrite, or inflate historical Garuda v3/V15/V45 evidence.

## Why V46 exists

The official challenge asks teams to combine flow-level and packet-level telemetry, learn network-state transitions, roll future states forward, estimate attacker progression, map supported behavior to MITRE ATT&CK stages, and explain the forecast. The historical 21-dimensional Garuda schema already covered the core graph/time-series world model, but did not explicitly cover every requested traffic attribute.

V46 closes the remaining feature-contract gap while preserving the strict V45 evaluation rules.

## Frozen 10-second feature contract

`garuda_v3.ps_complete.FEATURES` contains 34 bounded telemetry dimensions:

- traffic volume: flow, byte and packet counts plus mean duration;
- all requested TCP flags: SYN, ACK, RST, FIN, **PSH and URG**;
- bidirectional packet ratio and TCP/UDP fractions;
- IAT **mean, variance and maximum**;
- TCP receive-window statistic;
- TTL mean and variance;
- IP fragmentation fraction;
- payload-size **mean, variance and maximum**;
- unique destination-port activity;
- sequential and non-sequential/randomized port-transition fractions;
- retransmission indicator fraction **and count**;
- explicit availability flags so unavailable telemetry is not silently fabricated.

Source/destination endpoints and directed graph edges remain structural graph evidence rather than learned endpoint IDs.

### Scan feature boundary

Sequential/randomized port-transition values are descriptive observed-traffic features. They are **not attack labels** and they do not by themselves prove reconnaissance.

### Retransmission boundary

Retransmissions are approximated from duplicate positive-payload TCP `(src, sport, sequence, payload_length)` segments within the observation window. This is useful packet evidence, not full TCP stream reconstruction.

## Raw PCAP preparation

Example:

```bash
python -m garuda_v3.ps_complete capture.pcap \
  --output datasets/v46/campaign-a.npz \
  --campaign campaign-a --family infiltration \
  --mode host --max-nodes 128
```

Raw PCAP preparation always starts with `y=-1` (unknown). A packet capture does not establish malicious/benign truth by itself.

Reviewed annotations may be attached explicitly:

```bash
python -m garuda_v3.ps_complete capture.pcap \
  --output datasets/v46/campaign-a.npz \
  --campaign campaign-a --mode host \
  --annotations reviewed-campaign-a.json
```

The existing five supported stage targets remain:

- Reconnaissance / MITRE TA0043
- Initial Access / TA0001
- Lateral Movement / TA0008
- Command & Control / TA0011
- Exfiltration / TA0010

Missing tactic truth remains unknown; it is never converted to a negative stage label.

## Historical IDS2018 development diagnostic

For engineering diagnostics only, V46 can reproduce the repository's frozen schedule-assisted IDS2018 convention with:

```bash
--weak-ids2018-schedule
```

Those labels are explicitly marked:

- `release_evidence_eligible=false`
- `verified_incident_records=0`
- `stage_supervised=false`

They may be used to find model/data failures. They may **not** support claims of verified compromise prediction, unseen final-test performance, supervised MITRE accuracy, or production readiness.

The CI diagnostic uses the already exposed split:

- train: `Thursday-22-02-2018`
- validation: `Friday-23-02-2018`
- test: `Thursday-01-03-2018`, `Friday-02-03-2018`

and therefore labels its scope `development_reused_holdout`.

## State-first training

`garuda_v3.train_v46` keeps the V45 discipline:

1. train future-state dynamics first;
2. include epoch-0 residual persistence as the baseline;
3. select the state checkpoint only on validation state MSE;
4. do not train/promote the risk head unless validation beats persistence;
5. freeze the state model before fitting the risk head;
6. fit calibration and the <=1% FPR alert policy on validation only;
7. evaluate LR, LSTM and GNN+LSTM with the same observed history;
8. train the five-stage head only with explicit `stage_y` supervision;
9. never approve automatic containment from model metrics alone.

Unlabelled PCAP telemetry can still train the world-model state transition using `--state-only`; risk labels are not invented merely to make training run.

## Three-seed diagnostic

The pull-request workflow `.github/workflows/v46-ps-diagnostic.yml` prepares the four committed IDS2018 PCAP captures at 10-second resolution and runs seeds **42, 43 and 44**. It reports every seed and a mean/sample-SD summary; it does not choose the best seed.

This workflow is deliberately a **development diagnostic**, not the final SIH benchmark, because those campaigns have already been inspected and their timing labels are weak.

## What is still required for release-grade SIH evidence

V46 does not manufacture missing evidence. A final release claim still requires:

1. raw CICAPT/other compatible packet telemetry prepared under the same 10-second feature contract;
2. a genuinely new campaign split frozen before test inspection;
3. independently reviewed attack/compromise timestamps;
4. clean-history future-positive incidents for measured pre-compromise lead time;
5. explicit positive/negative MITRE tactic intervals for stage training/evaluation;
6. per-family support and the frozen gate of FPR <=1% and recall >=80%;
7. state forecasting that beats persistence across the fixed seeds;
8. campaign-level uncertainty rather than treating seed repeats as independent evidence.

Until those inputs exist, the correct status is **research/development evidence**, not verified pre-compromise production forecasting.
