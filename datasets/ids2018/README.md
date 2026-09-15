# Original CSE-CIC-IDS2018 PCAP subset

Source: Communications Security Establishment and Canadian Institute for Cybersecurity, **CSE-CIC-IDS2018**. Retrieved 11 September 2026 from the public AWS bucket `cse-cic-ids2018`.

Required dataset citation and links:
- https://www.unb.ca/cic/datasets/ids-2018.html
- https://registry.opendata.aws/cse-cic-ids2018/
- Iman Sharafaldin, Arash Habibi Lashkari, Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” ICISSP 2018.

The publisher permits redistribution with attribution and the AWS registry link. This directory contains a selected subset, not the complete dataset. Captures record a controlled attack testbed, not an exhaustive collection of real-world zero-days.

| File in raw/ | Original captured host | Selection |
|---|---|---|
| Thursday-22-02-2018.pcap | 172.31.69.28 | Web-attack day, full selected member |
| Friday-23-02-2018.pcap | 172.31.69.28 | Web-attack day, full selected member |
| Thursday-01-03-2018.pcap | 172.31.69.13 | Infiltration day, **part 2 only**, about 32 minutes |
| Friday-02-03-2018.pcap | 172.31.69.23 | Botnet day, full selected member |

Four PCAP members total 199,958,864 bytes. `raw/Thursday-22-02-2018.log` is the matching publisher Ubuntu log for the web victim. It does not establish successful compromise. Raw captures were extracted by HTTP byte range, decompressed without execution, and verified against the ZIP member CRC. Each `.source.json` records the original URL/member, CRC and SHA-256. `catalog/` includes day archive sizes and nine ZIP member inventories; the 20-Feb archive is RAR and was not selectively extracted.

All ten daily PCAP archives total approximately 444.54 GiB; the local workspace had about 30 GiB available. The included selection covers four days and three coarse attack families. It does not cover all ten days, all seven advertised scenario categories, or all hosts.

`audit/` records preprocessing. Two web captures each end with an incomplete record. The bot capture contains 2,536 invalid IP-length records, affecting 104 one-minute windows. All affected graph windows are excluded. Original bytes remain unchanged. No packet length, payload, timestamp or missing window is fabricated.

`labelled/` contains **1,549 observed host/packet graph windows**, at 60 seconds and up to 64 nodes, including unknown labels. Labels are schedule-assisted **weak supervision**, not independently reviewed packet or MITRE ground truth. Positive windows require a published scheduled interval and observed traffic involving the published attacker endpoint. Boundary/ambiguous windows remain unknown. Negatives assume background outside the schedule is benign. Published wall times are interpreted as UTC-04:00 based on observed web-traffic alignment; the publisher page does not confirm this timezone explicitly. This assumption limits all reported label metrics.

The split was fixed before training: web day 22-Feb trains, web day 23-Feb validates, infiltration part 2 and botnet day test. Botnet/infiltration families are absent from training and validation; this is an **exploratory unseen-family test**, not proof of zero-day detection. Captures have different operating systems, sensors and graph distributions, creating important confounding.

Reproduce from the project root:

```bash
python -m garuda_v3.ids2018_prepare
python -m garuda_v3.ids2018_label
OPENBLAS_NUM_THREADS=1 python -m garuda_v3.train --graphs datasets/ids2018/labelled/Thursday-22-02-2018.npz datasets/ids2018/labelled/Friday-23-02-2018.npz datasets/ids2018/labelled/Thursday-01-03-2018.npz datasets/ids2018/labelled/Friday-02-03-2018.npz --split-manifest datasets/ids2018/split.json --decoder residual --epochs 20 --history 8 --horizon 4 --stride 2 --output garuda_v3/artifacts/ids2018_reproduced
python -m garuda_v3.ids2018_fit_gate --artifacts garuda_v3/artifacts/ids2018_reproduced
```

To redownload one verified original member if needed:

```bash
python -m garuda_v3.ids2018_fetch datasets/ids2018/catalog/Thursday-22-02-2018.members.json pcap/UCAP172.31.69.28 downloaded-web.pcap
```

The downloader enforces a 128-MiB compressed/512-MiB extracted member limit. Larger archives/members need a separately planned streaming workflow. Do not blindly extract or execute unrelated archive entries.

**Read `garuda_v3/IDS2018_RESULTS.md` for the failed holdout result. The new host checkpoint is research-only and was not promoted to the default demo.**
