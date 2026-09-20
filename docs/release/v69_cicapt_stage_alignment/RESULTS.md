# V69 CICAPT Publisher-Stage ↔ Network-Time Alignment Audit

Authoritative GitHub Actions run: `35525241720`. Status: **SUCCESS**.

## What was tested

The entire decoded IPv4 content of the CICAPT Phase-2 capture was scanned: **9,461,828 packets**, spanning **259,449.8985 seconds**. Publisher-style tactic event timestamps from the commit-pinned development timeline were mapped to exact 10-second network windows. Duplicate provenance rows at the same stage/time were collapsed so support could not be inflated by duplicate entities.

## Alignment result

- Unique required publisher-stage event windows: **20**
- Event windows with real packet-time alignment: **20 / 20**
- Aligned events still marked `network_stage_validated=false`: **20 / 20**

Unique aligned windows by requested stage:

| Stage | Unique aligned 10s windows |
|---|---:|
| Reconnaissance / Discovery | 9 |
| Initial Access | 1 |
| Lateral Movement | 3 |
| Command & Control | 4 |
| Exfiltration | 3 |

A predeclared minimum of 20 independent windows per class was required even for a basic held-out per-class stage metric. **None of the five classes meets that support floor.**

## Release decision

`supervised_network_stage_f1_release_claim_allowed = false`.

This is deliberately fail-closed. The timestamps align to real traffic, but alignment alone does not prove that every provenance tactic label is a validated network-window stage label. Reporting an F1 from 1 Initial-Access window or 3 Exfiltration windows would be misleading. A separate, better-supported stage benchmark is required.
