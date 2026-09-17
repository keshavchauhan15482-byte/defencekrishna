# V33 UNSW IoT Attack Traces support audit

V33 is a provenance/schema/support audit only. No forecasting model was trained and no FPR/recall/lead-time claim is made from this run.

Evidence run: GitHub Actions `35053985947`  
Job: `104660159735`  
Artifact: `garuda-v33-unsw-attacktrace-evidence` (`10430505155`)  
Artifact SHA256: `56f42bdc457e082db5752345ebaf25d00c13c22dcca7f889451458f97a9ef789`

## Source provenance

- `annotations.zip`: 10,918 bytes, SHA256 `1990c33d5430c4939336d79b08e9ba6a90a8c97621069cb748c3c0282d1eaafd`
- `flowdata.zip`: 6,332,624 bytes, SHA256 `04131cbe9ccd255b2bf001aaee029ae8e84f9542f7440412a1dd28ac80e40295`
- Publisher: UNSW IoT Analytics Research Group.

## Support result

- Annotation files: **15**
- Flow files: **11**
- Parseable timestamped attack events: **234**
- Events mapped to flow data: **234 / 234**
- Events with observable attack-free 8-minute prehistory: **199 / 234 = 85.04%**
- Distinct attack labels: **45**
- Attack duration: min **600 s**, median **600 s**, max **602 s**

Representative labels include TCP SYN device/reflection attacks, ARP spoofing, Ping of Death, UDP-device attacks, Smurf, SSDP and SNMP variants at multiple rates/directions.

Pre-frozen suitability rule: at least 5 independently annotated events with observable attack-free 8-minute prehistory and at least 2 attack labels. **PASS**.

## Interpretation

This is a major support improvement over the sparse IoT-23 clean-onset development set. The corpus provides hundreds of explicitly timestamped attacks and enough observable pre-onset network history to support a real clean-history forecasting pilot with meaningful event-level lead-time evaluation.

It still does **not** prove pre-compromise prediction or universal zero-day prediction. V34 must freeze train/calibration/policy/test grouping and model/threshold rules before scoring held-out attacks. Final validation remains locked.
