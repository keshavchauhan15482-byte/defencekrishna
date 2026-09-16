# V48 — Fresh ToN-IoT unseen-family temporal transfer

V48 is the follow-up to V47. V47 showed two complementary facts on X-IIoTID:

1. the world model can transfer network-state dynamics to several held-out attack families;
2. the benign future-trajectory anomaly score alone has low unseen-family recall, while a known-family discriminative model transfers strongly to some families but exceeds the 1% FPR budget.

Those V47 outcomes are now development evidence. V48 freezes a hybrid design **before** looking at ToN-IoT family results and evaluates it on a fresh public dataset.

## Fresh dataset

ToN-IoT is maintained by UNSW Canberra and includes timestamped network traffic with benign/attack labels and attack types. V48 uses only the network-traffic table. Linux/Windows/process/telemetry datasets are not model inputs.

The CI workflow downloads the public `train_test_network.csv` mirror and records its SHA-256. Source/destination IPs are used only to group contiguous source-host timelines; they are not learned features.

## State representation

Each source host is aggregated into one-minute network states from a strict common numeric feature intersection:

- source/destination ports;
- duration;
- source/destination bytes;
- missed bytes;
- source/destination packet counts;
- source/destination IP-byte counts;
- flow count.

For each numeric field the state includes mean/std/max where available. No attack label, attack type, IP identifier, process field, OSSEC alert or host-resource value is a model feature.

## Temporal world model

- observed history: 8 minutes;
- future rollout: 4 minutes;
- state model: LSTM -> four future states;
- state objective: future-state MSE only;
- validation must beat exact persistence;
- test state MSE vs persistence remains separately reported.

## Unseen-family protocol

For held-out family `F`:

1. all histories/targets containing `F` are removed from train/calibration/policy;
2. partitions remain chronological with a 12-minute embargo;
3. test positives are final-tail sequences with `F` absent from observed history and appearing in the next 1-4 minutes;
4. test negatives are final-tail clean benign history + benign future;
5. `F` is used only to construct the split and score frozen predictions.

Families are selected by final-tail support count only, never model performance.

## Frozen V48 risk system

### Temporal known-family transfer

A separate LSTM risk model learns `benign vs future known attack` from the remaining attack families. It never receives the held-out family during training or calibration.

### World novelty

The state model predicts the four future network states. A robust clean-benign future forecast reference is built from family-free calibration traffic. Distance from this reference becomes a novelty score.

### Frozen hybrid

V47 development evidence showed that discriminative transfer supplied recall while world novelty supplied conservative false-alert behavior. Before ToN-IoT evaluation V48 freezes:

`hybrid = 0.75 * temporal-risk benign-percentile + 0.25 * world-novelty benign-percentile`

The score weights are not searched on ToN-IoT.

Policy threshold is fit from **benign policy traffic only** at a 0.5% empirical FPR reserve. The actual release requirement remains:

- held-out-family recall >= 80%;
- benign FPR <= 1%;
- adequate positive/negative support;
- state model beats persistence;
- all three seeds 42/43/44 pass.

Logistic Regression, temporal LSTM risk, world novelty and the frozen hybrid are all reported on identical test samples.

## Clean-history evidence

V48 separately reports positives where the complete observed 8-minute history contains no attack-labelled activity and the held-out family appears in the future. This is a stronger pre-onset proxy than ordinary family-disjoint recognition, but it is still **not verified compromise lead time**. A dataset attack label is not proof of successful compromise.

## Claim boundary

A passing result would support:

> Garuda generalises to a held-out attack family on a fresh timestamped public network dataset using a hybrid temporal/world-model risk design frozen before evaluation.

It would not prove a real undisclosed production zero-day, successful prevention, or verified pre-compromise lead time. Those require independently reserved live/lab campaigns with explicit successful-compromise outcome timestamps.
