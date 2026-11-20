# AIT three-campaign forecasting pilot: actual training, not a release gate

Scope: development diagnostic on publisher-generated synthetic enterprise traffic.
Fox trains, Harrison selects/calibrates, Russellmitchell is diagnostic evaluation.
This is NOT an untouched final, forward-calendar deployment, five-stage result,
verified compromise warning, production claim or a replacement for existing metrics.
Validation dates postdate the diagnostic evaluation dates: cross-campaign, not
prospective temporal deployment. Reserved wardbeck/wheeler/wilson remain undecoded.

## Protocol and results

The three archives contain 351,908 / 437,659 / 377,704 records. Completed-flow
features become available only at END time. Graphs have 21 legacy flow channels,
10-second protocol-service snapshots, 80-second histories and 10/20/30/40-second
targets. Missing packet channels remain absent; the 34-feature packet runtime is
not modified. Missing annotation labels remain unknown. Attack-family/MITRE and
successful-compromise labels are not invented from behaviour names.

Fixed pilot configuration: seeds 42/43/44, 5 state epochs, 5 risk epochs, stride 24,
patience 3, residual decoder and 1% validation FPR budget. State learns first;
the state backbone freezes before risk fitting. This is a short pilot, not a claim
of converged or optimal training. Per-seed reports retain all model outcomes.

Eligible sequence counts: train 446, validation 553, diagnostic 407.
The diagnostic has 361 positives and 46 negatives; windows are correlated.
Zero observed validation false alerts cannot establish a 1% population FPR:
the reported validation upper interval is about 4.8%, before dependence corrections.

| Model | Mean test state MSE | Improvement vs persistence | Mean recall | Mean FPR | Mean F1 |
|---|---:|---:|---:|---:|---:|
| Persistence | 0.060632 | reference | not a deployable alert | not applicable | not applicable |
| LSTM | 0.045238 | 25.39% | 5.26% | 4.35% | 9.64% |
| GNN+LSTM | 0.044567 | 26.50% | 7.29% | 6.52% | 12.57% |
| Equal-history LR | not a state forecaster | not applicable | 40.44% | 32.61% | 55.94% |

These are seed means on one cohort, not independent-campaign confidence intervals.
The deterministic LR baseline repeats across seeds; it is not three experiments.
The state model learns useful future dynamics, but the risk policy does NOT meet
80% recall / 1% FPR. No production weights were promoted.

## Follow-up risk-head diagnostic

After the above cohort was exposed, a train-only ExtraTrees history skip and a
history-plus-learned-rollout readout were compared, selecting by validation recall,
then FPR, then Brier. No evaluation labels selected the winner, but the experiment
itself followed an exposed failure: it remains POST-EXPOSURE development evidence.
Selection chose history-only in 2/3 seeds and augmented history in 1/3 for each
backbone. It did not establish a robust rollout-specific risk contribution and
did not pass the operational gate. All outcomes are preserved, not cherry-picked.

## Reproduce

```sh
for c in fox harrison russellmitchell; do
 python -m garuda_v3.ait_source_audit --campaign "$c" --cache /path/cache --output "/path/cache/$c-audit.json"
 python -m garuda_v3.ait_forecast_data --campaign "$c" --cache /path/cache --output "/path/cache/$c-graph.npz"
done
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.ait_diagnostic --cache /path/cache --output /path/new-run
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.ait_skip_diagnostic --cache /path/cache --backbones /path/new-run --output /path/new-skip
```

The raw data archive is not committed. Protocol, source/graph hashes, per-seed
reports and trained backbone checkpoints are kept in the diagnostic artifact lane.
They do not alter the active runtime bundle. The direct V45-core entrypoint now
defaults to development scope; only the strict wrapper explicitly requests the
predeclared-holdout label after its reservation preflight.
