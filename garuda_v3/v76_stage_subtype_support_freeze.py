"""V76 support-only Class3 subtype freeze for fresh five-stage generalisation.

This step intentionally performs NO model training or scoring. It freezes one fine-
grained X-IIoTID Class3 attack subtype per lifecycle stage using only temporal sequence
support counts. Reserve subtypes selected here can then be evaluated by a later V77
model run without choosing the holdout from model metrics.

Important: a four-minute future horizon can contain more than one subtype from the same
lifecycle stage. V76 therefore treats the target as (furthest future stage, set of
subtypes observed at that stage) instead of discarding multi-subtype horizons.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import HISTORY, HORIZON, detect_label_hierarchy, norm, parse_time, pick_col
from .v48_strict_runner import canonical_family_name
from .v71_future_stage_proxy import STAGES, stage_name

MIN_RESERVE_PER_STAGE = 20
MIN_DEV_PER_STAGE = 80
MAX_CANDIDATES_PER_STAGE = 3


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def subtype_name(value) -> str | None:
    text = canonical_family_name(value)
    if text in {"", "nan", "none", "normal", "benign", "attack"}:
        return None
    return text


def find_subtype_column(df: pd.DataFrame, binary_col: str, family_col: str) -> str:
    mapping = {norm(c): c for c in df.columns}
    if "class3" in mapping:
        return mapping["class3"]
    candidates = []
    for col in df.columns:
        if col in {binary_col, family_col}:
            continue
        key = norm(col)
        if "class" not in key and "label" not in key:
            continue
        values = df[col].dropna().astype(str).str.strip()
        uniq = {subtype_name(v) for v in values}
        uniq.discard(None)
        if len(uniq) > 5:
            candidates.append((len(uniq), col))
    if not candidates:
        raise RuntimeError("No trustworthy fine-grained subtype column found")
    candidates.sort(key=lambda row: (-row[0], row[1]))
    return candidates[0][1]


def build_minute_pairs(df, dt, binary, family, subtype_col):
    src_col = pick_col(df.columns, ["Scr_IP", "Src_IP", "Source_IP", "source_ip"])
    if src_col is None:
        raise RuntimeError("Source identity unavailable")
    base = pd.DataFrame({
        "dt": dt,
        "binary": binary,
        "family": family,
        "subtype": df[subtype_col],
        "src": df[src_col].astype(str),
    })
    base = base.dropna(subset=["dt", "binary"]).copy()
    base["binary"] = base["binary"].astype(int)
    base["minute"] = base["dt"].dt.floor("min")

    def pair_set(group):
        out = set()
        for attack, fam, subtype in zip(group["binary"], group["family"], group["subtype"]):
            if int(attack) != 1:
                continue
            stage = stage_name(fam)
            sub = subtype_name(subtype)
            if stage is not None and sub is not None:
                out.add((stage, sub))
        return tuple(sorted(out))

    rows = []
    for (src, minute), group in base.groupby(["src", "minute"], sort=True):
        rows.append({"src": str(src), "minute": minute, "stage_subtypes": pair_set(group)})
    return pd.DataFrame(rows), src_col


def make_sequence_metadata(minute_pairs):
    rows = []
    rank = {stage: i for i, stage in enumerate(STAGES)}
    for src, group in minute_pairs.groupby("src", sort=False):
        g = group.sort_values("minute").reset_index(drop=True)
        times = g["minute"].astype("int64").to_numpy() // 10**9
        pairs = g["stage_subtypes"].tolist()
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            stop = i + HORIZON + 1
            span = times[lo:stop]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            hist = set()
            future = set()
            for item in pairs[lo:i + 1]:
                hist.update(item)
            for item in pairs[i + 1:stop]:
                future.update(item)
            if future:
                furthest_rank = max(rank[stage] for stage, _ in future)
                target_stage = STAGES[furthest_rank]
                target_subtypes = frozenset(sub for stage, sub in future if stage == target_stage)
            else:
                target_stage = None
                target_subtypes = frozenset()
            rows.append({
                "src": str(src),
                "cutoff": int(times[i]),
                "history_pairs": frozenset(hist),
                "future_pairs": frozenset(future),
                "all_pairs": frozenset(hist | future),
                "target_stage": target_stage,
                "target_subtypes": target_subtypes,
            })
    if not rows:
        raise RuntimeError("No contiguous temporal sequences")
    return rows


def candidate_table(rows):
    total_stage = Counter(r["target_stage"] for r in rows if r["target_stage"] is not None and r["target_subtypes"])
    by_pair = defaultdict(int)
    clean_onset = defaultdict(int)
    for row in rows:
        stage = row["target_stage"]
        if stage is None:
            continue
        for sub in row["target_subtypes"]:
            pair = (stage, sub)
            by_pair[pair] += 1
            if pair not in row["history_pairs"]:
                clean_onset[pair] += 1

    table = {stage: [] for stage in STAGES}
    for (stage, subtype), target_support in sorted(by_pair.items()):
        reserve_pair = (stage, subtype)
        remaining_by_stage = {}
        for dev_stage in STAGES:
            remaining_by_stage[dev_stage] = sum(
                1 for r in rows
                if r["target_stage"] == dev_stage
                and r["target_subtypes"]
                and reserve_pair not in r["all_pairs"]
            )
        table[stage].append({
            "subtype": subtype,
            "target_support": int(target_support),
            "clean_onset_reserve_support": int(clean_onset[(stage, subtype)]),
            "remaining_stage_support_if_held_out_alone": remaining_by_stage,
        })
    for stage in STAGES:
        table[stage].sort(key=lambda r: (-r["clean_onset_reserve_support"], -r["target_support"], r["subtype"]))
    return table, {stage: int(total_stage.get(stage, 0)) for stage in STAGES}


def choose_combination(rows, table):
    pools = {}
    for stage in STAGES:
        eligible = [
            row for row in table[stage]
            if row["clean_onset_reserve_support"] >= MIN_RESERVE_PER_STAGE
            and row["remaining_stage_support_if_held_out_alone"][stage] >= MIN_DEV_PER_STAGE
        ][:MAX_CANDIDATES_PER_STAGE]
        if not eligible:
            raise RuntimeError(f"No support-qualified Class3 subtype for {stage}; candidates={table[stage][:12]}")
        pools[stage] = eligible

    best = None
    audits = []
    for combo in itertools.product(*(pools[stage] for stage in STAGES)):
        chosen = {stage: row["subtype"] for stage, row in zip(STAGES, combo)}
        reserve_pairs = {(stage, subtype) for stage, subtype in chosen.items()}
        reserve_support = {}
        dev_support = {}
        for stage in STAGES:
            pair = (stage, chosen[stage])
            reserve_support[stage] = sum(
                1 for r in rows
                if r["target_stage"] == stage
                and chosen[stage] in r["target_subtypes"]
                and not reserve_pairs.intersection(r["history_pairs"])
            )
            dev_support[stage] = sum(
                1 for r in rows
                if r["target_stage"] == stage
                and r["target_subtypes"]
                and not reserve_pairs.intersection(r["all_pairs"])
            )
        ok = all(v >= MIN_RESERVE_PER_STAGE for v in reserve_support.values()) and all(v >= MIN_DEV_PER_STAGE for v in dev_support.values())
        row = {"chosen": chosen, "reserve_support": reserve_support, "development_support": dev_support, "qualified": ok}
        audits.append(row)
        if not ok:
            continue
        objective = (
            min(reserve_support.values()),
            min(dev_support.values()),
            sum(reserve_support.values()),
            sum(dev_support.values()),
            tuple(chosen[s] for s in STAGES),
        )
        if best is None or objective > best[0]:
            best = (objective, row)
    if best is None:
        best_audits = sorted(
            audits,
            key=lambda r: (min(r["reserve_support"].values()), min(r["development_support"].values())),
            reverse=True,
        )[:10]
        raise RuntimeError(f"No five-stage subtype combination meets support gate; best={best_audits}")
    return best[1], pools


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    csv = Path(args.csv)
    df = pd.read_csv(csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    family = family.map(canonical_family_name)
    subtype_col = find_subtype_column(df, binary_col, family_col)
    minute_pairs, src_col = build_minute_pairs(df, dt, binary, family, subtype_col)
    sequences = make_sequence_metadata(minute_pairs)
    table, total_stage_support = candidate_table(sequences)
    selected, pools = choose_combination(sequences, table)

    reserve_pairs = {(stage, subtype) for stage, subtype in selected["chosen"].items()}
    reserve_touch_count = sum(bool(reserve_pairs.intersection(r["all_pairs"])) for r in sequences)
    output = {
        "protocol": "V76 support-only X-IIoTID Class3 unseen-subtype freeze",
        "dataset_sha256": sha256(csv),
        "selection_used_model_metrics": False,
        "model_scored_reserve_before_freeze": False,
        "binary_label_column": binary_col,
        "lifecycle_family_column": family_col,
        "fine_subtype_column": subtype_col,
        "source_column": src_col,
        "stage_mapping": {
            "Reconnaissance": "Reconnaissance",
            "Exploitation": "Initial Access proxy",
            "Lateral Movement": "Lateral Movement",
            "C&C": "Command & Control",
            "Exfiltration": "Exfiltration",
        },
        "minimum_reserve_per_stage": MIN_RESERVE_PER_STAGE,
        "minimum_development_per_stage": MIN_DEV_PER_STAGE,
        "max_candidates_per_stage": MAX_CANDIDATES_PER_STAGE,
        "selected_reserve_subtype_by_stage": selected["chosen"],
        "reserve_stage_support": selected["reserve_support"],
        "development_stage_support_after_all_reserves": selected["development_support"],
        "total_stage_support": total_stage_support,
        "reserve_touch_sequence_count": int(reserve_touch_count),
        "sequence_count": int(len(sequences)),
        "support_candidate_pools": {stage: pools[stage] for stage in STAGES},
        "all_candidate_support": table,
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method},
        "label_profiles": profiles,
        "target_rule": "furthest mapped lifecycle stage in the next four one-minute windows; all subtypes at that target stage are retained",
        "claim_boundary": "Support-only freeze. No model has been trained or scored on any selected reserve Class3 subtype. Exploitation remains an Initial Access proxy, not exact MITRE truth.",
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "dataset_sha256": output["dataset_sha256"],
        "fine_subtype_column": subtype_col,
        "selected_reserve_subtype_by_stage": selected["chosen"],
        "reserve_stage_support": selected["reserve_support"],
        "development_stage_support_after_all_reserves": selected["development_support"],
        "total_stage_support": total_stage_support,
        "sequence_count": len(sequences),
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
