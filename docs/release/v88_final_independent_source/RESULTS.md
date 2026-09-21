# V88 — Final Independent-Source Replication

**Authoritative GitHub Actions run:** `35563992781`  
**Workflow:** `V88 Final Independent-Source Replication`  
**Artifact:** `v88-final-independent-source-evidence` (artifact ID `10623820528`)  
**Artifact ZIP SHA256:** `0edba7ae94f03e46074bb1c2ea7502f0a86b91d512fb19d956cc77db4ba3faa3`  
**Evidence summary SHA256:** `51d4679615bf400a1d55ce6b9cb913f9c7a2912585190b172cbbdb514869d3a8`  
**Frozen protocol SHA256:** `8479ae7dae9b91087215637ee3757fcafe28abf39fee3f78e76582d62b4e3ffa`  
**Frozen Garuda config SHA256:** `0f064ffebb637597c19f359b9aff905fa8aafcfe493874550a6e70fa6f91ef78`

## Claim boundary

This is an **independent-source replication on public UNSW-NB15 cyber-range network traffic**. The four raw UNSW-NB15 shards are separate from the current X-IIoTID progression-development work. UNSW has appeared in earlier project research, so this run is **not** described as a fresh zero-day benchmark, organic production traffic, or verified pre-compromise evidence.

The V88 protocol was committed before scoring. Episode selection used timestamp/support information only; test metrics were not used for model/fusion or episode selection. Garuda and Logistic Regression receive the same observed-history source. Logistic Regression uses no family identity or future/test features, and its threshold is selected from clean policy negatives only.

## Independent-source result

Two independently selected attack-family episodes were evaluated. Garuda was run with seeds **42, 43, 44** for each family (6 seed-family evaluations total).

| Metric | Logistic Regression | Garuda (3-seed macro) | Garuda − LR |
|---|---:|---:|---:|
| Recall | 100.0000% | **98.6772%** | -1.3228 pp |
| False-positive rate | 11.6544% | **0.2871%** | **-11.3674 pp** |
| Precision | 51.6380% | **91.2083%** | **+39.5703 pp** |
| F1 | 57.6993% | **94.7874%** | **+37.0882 pp** |

The main independent-source advantage is not a higher recall point estimate: LR reaches 100% recall. Garuda retains **98.68% recall while reducing macro FPR from 11.65% to 0.287%** (about a 40.6× lower FPR) and raises macro F1 from 57.70% to 94.79%.

## Family-level evidence

### Backdoor

Test support: **315 positives / 9,360 negatives**.

Logistic Regression: TP 315, FN 0, FP 25, TN 9,335; recall **100%**, FPR **0.2671%**, precision **92.6471%**, F1 **96.1832%**. Recall Wilson-95 lower bound **98.7952%**; FPR Wilson-95 interval **0.1810%–0.3940%**.

Garuda 3-seed mean: recall **99.5767%** (SD 0.4849 pp), FPR **0.2849%** (SD 0.0527 pp), precision **92.1808%**, F1 **95.7305%**.

### Analysis

Test support: **120 positives / 4,379 negatives**.

Logistic Regression: TP 120, FN 0, FP 1,009, TN 3,370; recall **100%**, FPR **23.0418%**, precision **10.6289%**, F1 **19.2154%**. Recall Wilson-95 lower bound **96.8981%**; FPR Wilson-95 interval **21.8185%–24.3123%**.

Garuda 3-seed mean: recall **97.7778%** (SD 3.8490 pp), FPR **0.2893%** (SD 0.0264 pp), precision **90.2357%**, F1 **93.8444%**.

## Dataset provenance

| Raw shard | Rows | SHA256 |
|---|---:|---|
| `UNSW-NB15_1.csv` | 700,001 | `7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511` |
| `UNSW-NB15_2.csv` | 700,001 | `6130ad02873cc6069ae695cf2844f2e8c2e9a9a1b7532dd82ab8f202757cacf8` |
| `UNSW-NB15_3.csv` | 700,001 | `ae990a96c3dfcd425ce2801aadb1727a34d5e0ae6d8215dbcdae60dedfaef640` |
| `UNSW-NB15_4.csv` | 440,044 | `cdf563692d51d405541dd659ddcdad9fa01f001f05fe9fc4b67f00ca12fbc96a` |

## What V88 supports

- Strong **independent-source attack-generalisation replication** on public cyber-range traffic.
- A real low-FPR operating point: macro Garuda FPR **0.2871%**, below the project's 1% target on these two episodes.
- High attack recall: macro **98.6772%** on these two episodes.
- Strong same-input baseline evidence: the gain is primarily much lower false positives and much higher precision/F1.

## What V88 does not support

- It is not a newly sealed zero-day campaign.
- It is not organic production/customer traffic.
- It does not prove attacker-stage/progression accuracy.
- It does not prove verified lead time to successful compromise.
- It does not authorize autonomous enterprise containment.
