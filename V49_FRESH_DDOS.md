# V49 — Fresh unseen-DDoS campaign forecast

V49 is the first attack-bearing fresh campaign test after V47 exposed low open-set recall and V48 showed that the ToN-IoT train/test final chronological tail contains no attack-family onsets.

## Frozen campaign roles

These roles are declared before model evaluation on the final campaign:

- **Train:** CSE-CIC-IDS2018 BruteForce (14-Feb) + Botnet (2-Mar)
- **State validation + probability calibration:** Infiltration (28-Feb)
- **Policy threshold:** Web attacks (22-Feb), using benign windows only for the 0.5% FPR reserve
- **Final:** DDoS (21-Feb; HOIC / LOIC-UDP)

The DDoS family/day is absent from all fitting, scaling, state checkpoint selection, calibration and policy selection. The final campaign file hash is recorded and its labels are used only for evaluation.

## Representation

CICFlowMeter rows are timestamped. A fixed flow-only feature contract is aggregated into **10-second global network-state vectors**. It includes traffic volume, bidirectional packet/byte statistics, IAT mean/std/max, packet-length statistics, TCP SYN/ACK/RST/PSH/URG counts, TCP initial-window statistics and active/idle timing. Label and timestamp fields are never model features.

- History: 8 × 10s = 80 seconds
- Future rollout: 4 × 10s = 40 seconds
- State model: residual-style temporal LSTM trained on future-state MSE
- Persistence gate: validation state MSE must beat exact persistence

The global vector path is intentionally separate from V46's packet+graph contract; V49 tests unseen-family temporal transfer, not packet-feature completeness.

## Frozen risk design

The risk design is inherited without tuning from V48/V47 development:

- temporal known-family LSTM risk percentile: 75%
- world-future novelty percentile: 25%
- policy threshold: benign policy traffic only, 0.5% empirical FPR reserve
- release gate: final benign FPR <=1%, unseen-DDoS recall >=80%, state persistence gate passes, all seeds 42/43/44 pass

Logistic Regression, temporal risk LSTM and world novelty are reported separately on the same final samples.

## Strong pre-onset subset

V49 separately evaluates **clean-history future-positive** DDoS sequences: all eight observed 10-second states are benign-labelled, while a DDoS-labelled state appears in the next 10/20/30/40 seconds. This is an attack-onset forecast proxy and gives measurable warning horizon support.

It is still not verified compromise lead time. A DDoS flow label marks malicious traffic, not proof that compromise has completed.

## Claim boundary

A passing result can support:

> Garuda forecasted a fresh DDoS attack campaign/family excluded from all model-development stages, under a fixed 10-second temporal protocol.

It cannot support `real undisclosed zero-day prevented`, verified compromise lead time, or autonomous enterprise containment.
