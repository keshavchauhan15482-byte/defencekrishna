# V49 fresh unseen-DDoS campaign results

V49 is the first fully executed fresh attack-bearing family/day test after the V47 open-set diagnostic and V48 ToN-IoT support audit. It is intentionally a hard cross-campaign/domain test.

## Frozen protocol

- 10-second network states
- 8 observed states = 80 seconds history
- 4 future states = 10/20/30/40 seconds
- seeds 42/43/44; no best-seed promotion
- train: CIC-IDS2018 14-Feb BruteForce + 2-Mar Botnet
- state validation / probability calibration: CIC-IDS2018 28-Feb Infiltration
- benign policy threshold: CIC-IDS2018 22-Feb Web
- final unseen positive campaign: CIC-IDS2018 21-Feb DDoS HOIC/LOIC-UDP
- final clean-negative campaign: CICIDS2017 Monday GeneratedLabelledFlows, documented benign-only traffic
- feature contract frozen from development campaigns only; final files only validate availability of the frozen columns
- frozen risk fusion: 75% temporal LSTM risk + 25% world-future novelty
- policy FPR reserve: 0.5%
- requested release gate: final FPR <=1%, unseen-DDoS recall >=80%, state validation beats persistence, all three seeds pass

The final DDoS day and final benign day are excluded from all scaling, checkpoint selection, calibration, threshold selection and fusion-weight selection.

## Support

- train sequences: **6,354**
- calibration sequences: **3,340**
- policy sequences: **3,268**
- final unseen-DDoS future-positive sequences: **313**
- final independent clean benign sequences: **2,878**
- clean-history future-positive DDoS sequences: **0**

The DDoS positives first appear within the future horizon as:

- 10 seconds: 251 sequences
- 20 seconds: 32
- 30 seconds: 15
- 40 seconds: 15

However, none of these 313 sequences has a fully benign-labelled 80-second observed history. Therefore this test measures future-DDoS recognition/transfer, **not clean-history pre-onset warning**.

## State forecasting

All three seeds beat persistence on the development validation campaign:

| Seed | Validation model MSE | Validation persistence MSE | Gate |
|---:|---:|---:|---|
| 42 | 24.0263 | 44.9491 | pass |
| 43 | 24.0178 | 44.9491 | pass |
| 44 | 24.0204 | 44.9491 | pass |

But the same learned dynamics fail to transfer to the combined fresh DDoS-positive + independent benign-negative evaluation domain:

| Seed | Final model MSE | Final persistence MSE | Result |
|---:|---:|---:|---|
| 42 | 106801.13 | 87352.31 | worse |
| 43 | 106800.54 | 87352.31 | worse |
| 44 | 106804.23 | 87352.31 | worse |

This is strong evidence of campaign/domain shift. A validation persistence win is not sufficient to establish unseen-family rollout quality.

## Unseen-DDoS risk result

| Readout | Recall mean ± SD | FPR mean ± SD | Release interpretation |
|---|---:|---:|---|
| Frozen hybrid | **0.00% ± 0.00** | **0.602% ± 1.043 pp** | fails recall |
| Temporal risk LSTM | **0.00% ± 0.00** | **0.834% ± 1.444 pp** | fails recall |
| World novelty | **0.00% ± 0.00** | **0.000% ± 0.000** | abstains/misses all |
| Logistic history baseline | **86.90%** | **58.90%** | recall transfers, FPR unusable |

Per seed the frozen hybrid produced:

- seed 42: 0/313 DDoS detections; 52/2,878 false alerts = 1.807% FPR
- seed 43: 0/313 DDoS detections; 0 false alerts = 0% FPR
- seed 44: 0/313 DDoS detections; 0 false alerts = 0% FPR

The logistic baseline detected 272/313 DDoS sequences for every seed-equivalent run, but falsely alerted on 1,695/2,878 benign sequences. This demonstrates attack-family transfer signal exists in the observed history, while the current calibration/domain-normalization strategy does not transfer safely.

## Release gates

- unseen-family release gate: **FAIL**
- clean pre-onset gate: **FAIL / unsupported**
- verified compromise lead time: **unavailable**
- automatic containment approval: **false**

No 10/20/30/40-second success claim is made: frozen-hybrid recall is 0% at every horizon. The horizon values are future-window distances, not compromise lead times.

## Main technical finding

V49 isolates the next bottleneck clearly:

1. **Known-family discriminative features transfer to unseen DDoS** (86.9% LR recall), so the telemetry contains cross-family attack signal.
2. **Absolute-domain calibration does not transfer**: the LR FPR explodes on an independent benign domain.
3. **Current risk LSTM and world novelty become over-conservative** under the validation/policy thresholds and miss all DDoS positives.
4. **World-state dynamics also shift**: the learned state model is worse than persistence on the fresh evaluation domain.

The next development should therefore target domain-invariant/relative temporal representations and domain-aware calibration using development data only. V49 is now exposed evidence and must not be retuned and re-presented as a fresh final holdout.

## Reproduction

GitHub Actions V49 run `35093590478` completed successfully end-to-end. It downloaded the original timestamped CIC-IDS2018 flow files plus the timestamp-preserving CICIDS2017 `GeneratedLabelledFlows` Monday benign control, executed all three seeds, printed the summary and uploaded the immutable evidence artifact. The full Krishna integration regression also passed on the same PR head.
