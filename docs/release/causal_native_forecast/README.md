# Native future-head diagnostic and forecasting safeguards

**Scope:** an additive flow-record research experiment. Six trained checkpoints,
source hashes, frozen policies, all seed results and the failed source-quality
attempt are included. This is not a replacement for the active 34-feature packet
model, a certified advance-warning result, or an enforcement release.

## Concrete changes

- Publisher flow copies carrying different MITRE tactics are merged by UID,
  timestamp and network tuple. Packets and bytes count once. Conflicting labels
  remain unknown; overlapping native tactics are multi-label targets.
- Explicit destination-port/service features preserve network semantics. No IP
  identity, date, tactic, PID or future target enters model inference.
- State learning precedes risk/tactic readout learning. The latter cannot change
  state parameters. Epoch zero is persistence, and validation selects the state
  candidate. An unsuccessful candidate remains unpromoted.
- Four future heads cover 10/20/30/40 seconds. Calibration and thresholds use
  development validation only. Seeds 42/43/44 are all reported; no best seed is
  selected from final performance.
- Unknown labels, incomplete windows and unbounded completion times cannot
  become benign labels. Zero positive support produces null attack recall/F1,
  not a fabricated 0% failure or a PASS.
- The packet-backbone head runner also controls the **actual any-horizon alert**
  with a validation-only joint threshold. Four separately acceptable 1% rules
  cannot be OR-ed into a larger false-alert rate and still be called 1%.
- Objective replay now explicitly distinguishes campaign-first-success recall
  from event recall when a campaign has multiple objective success records.
  Warning/event timestamp ordering alone is not claimed as forecast accuracy.
- An offline three-seed readout exposes state uncertainty, future scores and
  gradient-times-input sensitivities. Unsupported tactics abstain. It has no
  containment capability and never declares a live warning from a replay.

## Reproducible source protocol

Publisher: [University of West Florida Cyber Analytics Research Group](https://datasets.uwf.edu/).
Data are published under [CC BY](https://creativecommons.org/licenses/by/4.0/).
The study uses native labels from UWF-ZeekData22, UWF-ZeekData24 and
UWF-ZeekDataFall24-2 for development. UWF-ZeekDataSum25-1 is the held-out release.
Dataset-defined sources are dated, hashed and retained in the protocols.
Validation days are disjoint from training days, within the development exercise;
this is not a claim that every development split is a different enterprise.

The initial two reserve attack shards did not yield contiguous 80s history + 40s
future observations. Their weeks did not overlap the available publisher benign
CSV. They were not scored. `initial_protocol.json`, the original model freeze and
the source-quality failure are preserved. The amended protocol adds two calendar
weeks that overlap the same publisher's benign export. All six checkpoints,
calibration and thresholds stay byte-identical; no refit follows the amendment.
The additional weeks yielded **41,588 sequences across 14 source days, with zero
future-positive attack targets**. They support a benign dynamics/false-alert
diagnostic, not an attack-recall or pre-compromise benchmark.

Artifacts: [`report.json`](../../../garuda_v3/artifacts/causal_native_flow/report.json),
[`freeze.json`](../../../garuda_v3/artifacts/causal_native_flow/freeze.json),
[`initial_freeze.json`](../../../garuda_v3/artifacts/causal_native_flow/initial_freeze.json).
[`reproduction.json`](../../../garuda_v3/artifacts/causal_native_flow/reproduction.json)
records a second frozen evaluation: six byte-identical checkpoints, identical
model/baseline metrics, and 325 passing local regressions (three skipped).

## Observed numbers

These numbers use an **earliest session-end proxy**, not verified exporter receipt
times. Mean ± SD is across three seeds; it is not a confidence interval over attacks.
State intervals in the detailed report bootstrap source days, not individual
overlapping sequences or independent enterprises.

| Model | Relative MSE improvement over persistence | State comparison gates | Attack recall / five-stage performance |
|---|---:|---:|---|
| LSTM | 11.07% ± 2.50 percentage points | 3/3 seeds | Not measurable: final positive support is zero |
| GNN+LSTM | 8.80% ± 2.10 percentage points | 3/3 seeds | Not measurable: final positive support is zero |

The GNN+LSTM **mean** false-alert rates are 0.0112%, 0.0224%, 0.5659%, 0.3070%
at 10/20/30/40 seconds. One seed exceeds 1% at the 30-second horizon; averaging
does not turn this into an all-seed policy PASS. The LSTM head is less stable:
mean false-alert rates are approximately 18.2%, 21.8%, 14.0%, 13.9%.
The equal-history logistic baseline is approximately 0.2885% at each horizon.
These rates refer to this benign-only record cohort, not universal attack detection.
Risk and five-stage release gates remain unestablished. Development sequence
support trained a usable Reconnaissance readout; the other four future tactic
readouts lack sufficient development support and remain unsupported.

## Timestamp contract: the important limitation

[Zeek's connection-log documentation](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)
defines `ts` as first-packet time and notes that `duration` excludes some trailing
TCP packets. A connection's log may also be exported later. Therefore
`ts + duration` is an **earliest-end proxy**, not proof that all finished-flow
statistics were available at that instant. This study is explicitly flagged
`record_availability_certified: false`. Its improvements do not certify causal
live forecasts or warning before compromise.

For a timing-backed run, supply a hash-pinned `availability_receipts_path` and
`availability_receipts_sha256` on each source. JSONL records contain `uid`,
`first_packet_ts`, `received_at_utc_epoch`. Every flow and matching benign record
must have a receipt. Receipt times may not precede the observed session span.
The graph enters at receipt time; no finished-flow statistics enter earlier.
Receipts must originate from an independently reviewed sensor/exporter log.
Raw packet windows with an independently matched attack/compromise timeline are
another route to actual causal availability; the active packet path already keeps
network features and post-hoc annotations separate.

## Run offline

Install research dependencies (Arrow is needed for preparation, not checkpoint inference):

```bash
python -m pip install -r garuda_v3/research_requirements.txt
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m garuda_v3.causal_stage_forecast \
  --protocol docs/release/causal_native_forecast/initial_protocol.json \
  --cache garuda_v3/runtime/native-sources --output garuda_v3/runtime/native-original
```

The original reservation correctly reports insufficient usable final telemetry.
To reproduce the frozen amended evaluation:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m garuda_v3.causal_stage_forecast \
  --protocol docs/release/causal_native_forecast/amended_protocol.json \
  --original-protocol docs/release/causal_native_forecast/initial_protocol.json \
  --frozen-experiment garuda_v3/artifacts/causal_native_flow \
  --cache garuda_v3/runtime/native-sources --output garuda_v3/runtime/native-final
```

The published directory includes `initial_freeze.json`, which the runner selects
and verifies against the amended protocol. An original experiment directory with
only `freeze.json` also works. The amended evaluation freeze cannot substitute
for the initial candidate freeze.
Every output directory must be new. No test source fits normalization,
calibration, class weights or policy thresholds.

Observed-graph inference (JSON contains only schema/features/mode/window_seconds,
eight contiguous UTC times, x/adj/mask; future labels and extra fields are rejected):

```bash
python -m garuda_v3.causal_shadow \
  --bundle garuda_v3/artifacts/causal_native_flow \
  --observed-history observed-history.json --output new-shadow-forecast.json
```

The reported retrospective origin is separate from the actual computation time.
Outputs are shadow scores, not authorized block decisions. A malformed input,
unsupported stage or failed gate never becomes a benign or certified verdict.

## What still establishes a 9/10 forecasting claim

Frozen evaluation must contain independently verified attack progression and
successful-compromise events from the same sensor/campaign as the raw telemetry,
with sufficient clean or explicitly uncompromised precursor histories. Report
misses, abstentions and false alerts alongside first-warning lead time. Require
positive lead time, a supported improvement over persistence/LSTM, adequate
per-family recall/FPR and sufficiently supported future tactics. Code, source
discovery and benign-only dynamics improvements do not replace that evidence.
