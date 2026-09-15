# V10 — Dataset-separated forecasting and targeted training fixes

No new dataset was added. All V9 data, checkpoints and reports are preserved.
The same LSTM and directed GraphSAGE+LSTM architectures were trained on IDS2018
only, CICAPT only, and combined development data. State-only and legacy joint
objectives were compared under the same V10 configuration: 36 fitted runs total
(3 source sets × 2 architectures × 2 objectives × 3 seeds).

## Main result: measurable state forecast improvement

Held-out CICAPT phase 2, 270 examples, four one-minute horizons. Values are mean
MSE ± sample standard deviation across seeds 42, 43, 44. Lower is better.

| Development data | Corrected LSTM | Corrected GNN+LSTM |
|---|---|---|
| ids_only | 0.010279 ± 0.001280 | 0.013177 ± 0.001736 |
| cicapt_only | 0.008664 ± 0.000237 | 0.009285 ± 0.000269 |
| combined | 0.008426 ± 0.000106 | 0.008799 ± 0.000085 |

Persistence MSE: **0.009824** (unrounded 0.009823641739785671).

- Combined LSTM: **14.23% lower MSE than persistence**.
- Combined GNN+LSTM: **10.43% lower MSE than persistence**.
- For both combined state-only models, each seed's paired 95% block-bootstrap
  interval for model-minus-persistence MSE lies below zero on this phase.
- GNN+LSTM still does not outperform LSTM here. GNN is an evaluated option, not a
  justified accuracy upgrade over LSTM in these results.
- IDS-only transfer remains weak, especially for GNN. Better training selection
  does not guarantee generalisation to a different traffic domain.

These are relative reductions in traffic-state forecast error, NOT attack
accuracy, attack recall, prevention success or percentage of attacks blocked.

## Controlled V10 correction comparison

Same maximum epoch budget, seeds, architecture and source splits for both arms.
The legacy arm uses the existing residual joint loss and mixed-loss checkpoint
selection. The corrected arm uses state MSE and includes epoch 0 in selection.

| Combined-data model | Legacy joint MSE | Corrected state MSE | Error reduction |
|---|---|---|---|
| lstm | 0.011727 | 0.008426 | 28.15% |
| gnn_lstm | 0.011730 | 0.008799 | 24.99% |

This compares a pair of changes together; it does not isolate the individual
causal contribution of loss separation versus checkpoint selection. V9 used a
smaller epoch budget and different calibration/weighting settings, so a raw
V9-to-V10 difference should not be presented as a controlled single-change test.

## Implemented fixes

1. **Separate state learning from risk supervision.** The state-only objective
   learns observed future traffic even when risk labels are unknown. It has no
   attack-label gradient. The legacy joint objective remains as an explicit
   experimental control, not an erased historical result.
2. **Select on the metric being evaluated.** State checkpoints use validation
   state MSE, not mixed BCE/Gaussian loss. Exact-persistence epoch 0 participates
   in selection; training cannot force a worse validation checkpoint to win.
   This does not promise a lower error on unseen data.
3. **Withhold unreliable confidence intervals.** The prior implementation used
   a whole-sample bootstrap block on tiny holdouts, yielding misleading
   zero-width intervals. Fewer than 40 examples now returns an unavailable
   interval. Existing historical reports are retained; V10 evidence is corrected.
4. **Separate state output from attack decisions.** V10 state inference has an
   explicit offline API/CLI and local gradient-times-input state explanations.
   It returns future feature states and validation-derived descriptive error
   bands. The attack-score API rejects these research checkpoints; an untrained
   or uncalibrated risk output cannot become a containment signal.
5. **Reproducibility and integrity.** Frozen source split/configuration, three
   seeds, training curves, selected epochs, checkpoint hashes, per-feature and
   per-horizon errors, per-seed intervals and raw predictions are included.

## Experimental protocol and limits

- Common representation: 64-slot observed host graph, 21 existing physical/log
  features, 60-second windows, history 8, horizon 4, stride 16. GraphSAGE widths
  12 and LSTM hidden width 16 are unchanged.
- Seeds: 42, 43, 44. Maximum 40 epochs, Adam learning rate .003, batch size 32,
  patience 10. Early stopping can use different epoch counts by objective.
- IDS development: 22 Feb, 23 Feb and 2 Mar captures already present in V9.
  CICAPT development: phase 1. For each development capture, first 70% training,
  later validation after 12-window embargo. No sequence crosses a gap or source.
- Test sources are excluded from fitting and checkpoint selection: CICAPT phase
  2 and the existing 15 Feb DoS capture. **Both have been evaluated previously.**
  This is a reused-holdout diagnostic, not a new independent generalisation gate.
- The DoS diagnostic has only **8 examples** under this fixed stride/continuity
  setup. Point errors are reported, but confidence intervals are withheld.
- Seed variation is not independent capture replication. The CICAPT block
  intervals describe correlated samples within one phase, not population-wide
  confidence. No holdout-guided hyperparameter sweep was performed.
- The strongest average tested state candidate is combined-data LSTM. A fixed
  seed-42 combined GNN example is also included for reproducible inspection;
  this seed was not selected for the best test score.
- State uncertainty uses validation absolute-error 95th percentiles. Bands are
  descriptive marginal error bands, not calibrated compromise probabilities or
  a guaranteed 95% joint trajectory interval.

## Still unresolved — do not call these fixed

| Requirement | V10 status |
|---|---|
| Traffic-state rollout better than persistence | Supported on the reused CICAPT phase for combined state-only LSTM/GNN |
| GNN improves over LSTM | Not demonstrated; LSTM remains stronger here |
| Independent cross-day/family FPR and recall | Not established by this state experiment |
| Verified pre-compromise warning lead time | Still needs independently verified incident/compromise timestamps |
| Supervised network MITRE stages | Not fixed; candidate provenance labels are not a verified complete network timeline |
| Production attack blocking and customer-pilot approval | Not established; existing defence model/defaults preserved |

Do not turn improved state MSE into a claimed 90% detection score or a market
readiness rating. New independent labelled evidence is still required for the
attack-warning and operational gates.

## Reproduce and inspect

From the project root, with the existing V9 prepared graphs:

```bash
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.v10_experiment
python -m unittest discover -s garuda_v3/tests
python -m garuda_v3.state_inference --model garuda_v3/artifacts/v10/combined_gnn_lstm_state_only_42 --graph datasets/multisource/graphs/cicapt_phase2.npz --output datasets/v10/state_forecast_example.json
```

The experiment resumes completed reports and refuses changed frozen settings.
Archive `garuda_v3/artifacts/v10` before a fresh full refit. The numerical results
are `datasets/v10/summary.json`; detailed runs and weights are under
`garuda_v3/artifacts/v10`. `state_forecast_example.json` is an offline forecast
from actual observed graph history, not a live sensor or evidence of blocking.
The new state-only checkpoint does not replace the existing production-facing
risk model. No website deployment or live network enforcement was performed.

## Verification

63 Python tests passed. All 36 fitted reports were checked; all 18 corrected state runs select validation MSE no worse than persistence. Every 8-example DoS bootstrap interval is withheld. Offline inference returned four finite future states with local sensitivity explanations and no attack or blocking decision.
