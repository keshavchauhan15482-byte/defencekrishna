# V34 UNSW flow-schema preflight

V34 is a schema/provenance preflight only. No forecasting model was trained and no performance claim is made from this run.

Evidence run: GitHub Actions `35054365994`  
Job: `104661297525`  
Artifact: `garuda-v34-unsw-schema-evidence` (`10430600554`)  
Artifact SHA256: `3501b2d965ad4044ee3ee84869a6278efec1b48c892752addb7008363ecd5617`

## Resolved schema contract

- Archive contains **10 real CSV flow files** plus one `.DS_Store` junk member.
- CSV delimiter: comma.
- Header present; first field is exactly `Timestamp`.
- Timestamp column index: **0**.
- Timestamp unit: **milliseconds since epoch**.
- All 10 real flow files support the same timestamp contract.
- Samples advance at approximately **one-minute cadence**.
- Remaining flow fields are numeric packet/byte counters plus final `NoOfFlows`.
- Device-specific flow widths vary (examples: **36, 42, 52, 80, 82, 124 columns**).
- `timestamp_contract_consistent = true`.
- `model_pilot_schema_ready = true`.

## Representation decision

Raw heterogeneous header fields must **not** be unioned directly into one cross-device model: the headers contain device-specific port/IP channels and their widths differ. The next pilot must convert every row into a canonical device-agnostic network representation by aggregating counters into generic categories such as total packets/bytes/flows, local/internet direction, TCP/UDP/ICMP/ARP, channel activity/sparsity and concentration. Raw device IDs, raw IP identities and raw port identities are not model features.

Combined with V33, the UNSW corpus now has **234 timestamped attacks**, **199 with observable attack-free 8-minute prehistory**, across **45 labels**, and a resolved one-minute flow schema. This is sufficient to start a real clean-onset cross-device forecasting pilot.

Final validation remains locked; V34 does not support any zero-day or pre-compromise accuracy claim by itself.
