# V50 — WUSTL-IIoT-2021 clean-history unseen-family support gate

V50 is deliberately a **support audit before training**. The current bottleneck is not another model architecture; it is obtaining a genuinely fresh chronological evaluation where an attack family excluded from development appears after a clean observed history.

WUSTL-IIoT-2021 is a useful candidate because it is a timestamped industrial testbed capture collected over roughly 53 hours and contains normal traffic plus DoS, reconnaissance, command injection and backdoor traffic.

## Leakage boundary

The WUSTL publisher explicitly warns that `StartTime`, `LastTime`, `SrcAddr`, `DstAddr`, `sIpId` and `dIpId` can expose attack identity and should not be used as predictive features when generalisation matters.

V50 therefore uses:

- `StartTime` only to reconstruct chronological order and splits;
- `Traffic` only as evaluation truth/family identity;
- none of the publisher-identified leakage fields as model features;
- no CSV row-order fallback if timestamps cannot be parsed.

No model is trained in V50 unless the support gate passes.

## Fixed temporal protocol

- observed history: 8 contiguous minutes;
- future horizon: 4 contiguous minutes;
- chronological partitions: 60% train, 15% calibration, 10% policy, final 15% test;
- 12-minute embargo between development partitions;
- held-out-family positive: family absent from all 8 observed minutes and appears in next 1–4 minutes;
- stronger clean-onset positive: complete observed history contains no attack-labelled traffic at all;
- negative: clean observed history and benign future in the final test tail.

## Training permission gate

A family becomes eligible for a fresh V50 model experiment only when the fixed final test tail contains at least:

- 20 clean-history future-positive sequences;
- 100 clean benign negatives;
- adequate family-free train/calibration/policy support.

If no family satisfies this before model fitting, V50 stops and reports a support limitation. The split will not be moved after inspecting family locations.

## Claim boundary

Passing this audit permits a model experiment; it proves no accuracy by itself. Even a later model pass would be an unseen-family / pre-onset public-dataset proxy, not verified successful-compromise lead time or a real undisclosed production zero-day.
