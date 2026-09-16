# V40 X-IIoTID stage-progression support audit

Authoritative run: GitHub Actions `35069434167` (job `104707190607`).
Evidence artifact: `garuda-v40-stage-progression-support-evidence` (`10435915483`), ZIP SHA256 `1b82194b3be288620e372467147bb78f10df78af4b1428869846d38e29f5b95e`.

V40 was a support-only audit. It trained no model and selected no threshold. It verified the known X-IIoTID transport file and mapped the `class2` stage field into the pre-frozen progression semantics.

## Mapped stage support

- Normal: **421,417** rows
- Reconnaissance: **127,590**
- Weaponisation: **67,260**
- Exploitation: **1,133**
- Lateral Movement: **31,596**
- Exfiltration: **22,134**
- Tampering: **5,122**
- Crypto-ransomware: **458**
- RDoS: **141,261**

## Frozen 8-minute history / 4-minute progression audit

- Eligible sequences: **25,961**
- Histories containing observable Reconnaissance/Weaponisation: **916**
- Observable-early histories followed by Exploitation-or-later within 4 minutes: **0**
- Observable-early negative histories: **916**
- Positive progression entities: **0**
- Distinct supported early-to-later stage pairs: **0**

All 916 observed-early sequences landed in the chronological training region; calibration, policy, and test had zero observed-early support under the frozen protocol.

## Decision

**V40 support gate: FAIL.**

This is a dataset/timeline-support failure, not a forecasting-model failure. Training a V41 progression forecaster on this protocol would be scientifically invalid because the positive class has zero support. X-IIoTID remains useful for the earlier future-malicious-traffic experiments, but it is rejected for this specific 8-minute early-stage -> 4-minute Exploitation-or-later progression protocol.

The next progression experiment must use a dataset/campaign with explicit security-event timestamps and multiple real early-to-later transitions. Final validation remains locked and must be newly reserved after the model/protocol is frozen.
