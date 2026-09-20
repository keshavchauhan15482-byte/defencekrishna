"""V76b bounded support-only Class3 holdout freeze.

V76's exhaustive support-only combination search was unnecessarily expensive. V76b
keeps the exact no-model contract, restricts each stage to its three strongest
support-qualified subtype candidates, and evaluates at most 3^5=243 combinations.
No model is trained or scored here.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path

import pandas as pd

from .v47_unseen_family import detect_label_hierarchy, parse_time
from .v48_strict_runner import canonical_family_name
from .v71_future_stage_proxy import STAGES
from .v76_stage_subtype_support_freeze import (
    MIN_DEV_PER_STAGE,
    MIN_RESERVE_PER_STAGE,
    build_minute_pairs,
    candidate_table,
    find_subtype_column,
    make_sequence_metadata,
    sha256,
)

MAX_CANDIDATES_PER_STAGE = 3


def choose_bounded(rows, table):
    pools = {}
    for stage in STAGES:
        eligible = [
            r for r in table[stage]
            if r["clean_onset_reserve_support"] >= MIN_RESERVE_PER_STAGE
            and r["remaining_stage_support_if_held_out_alone"][stage] >= MIN_DEV_PER_STAGE
        ][:MAX_CANDIDATES_PER_STAGE]
        if not eligible:
            raise RuntimeError(f"No support-qualified Class3 subtype for {stage}; candidates={table[stage][:12]}")
        pools[stage] = eligible

    best = None
    for combo in itertools.product(*(pools[s] for s in STAGES)):
        chosen = {stage: item["subtype"] for stage, item in zip(STAGES, combo)}
        reserve_pairs = {(stage, subtype) for stage, subtype in chosen.items()}
        reserve_support = {}
        development_support = {}
        for stage in STAGES:
            target_pair = (stage, chosen[stage])
            reserve_support[stage] = sum(
                1 for row in rows
                if row["target_stage"] == stage
                and row["target_subtype"] == chosen[stage]
                and target_pair in row["future_pairs"]
                and target_pair not in row["history_pairs"]
                and not (reserve_pairs - {target_pair}).intersection(row["all_pairs"])
            )
            development_support[stage] = sum(
                1 for row in rows
                if row["target_stage"] == stage
                and row["target_subtype"] is not None
                and not reserve_pairs.intersection(row["all_pairs"])
            )
        if not all(v >= MIN_RESERVE_PER_STAGE for v in reserve_support.values()):
            continue
        if not all(v >= MIN_DEV_PER_STAGE for v in development_support.values()):
            continue
        objective = (
            min(reserve_support.values()),
            min(development_support.values()),
            sum(reserve_support.values()),
            sum(development_support.values()),
            tuple(chosen[s] for s in STAGES),
        )
        row = {
            "chosen": chosen,
            "reserve_support": reserve_support,
            "development_support": development_support,
            "objective_support_only": [objective[0], objective[1], objective[2], objective[3]],
        }
        if best is None or objective > best[0]:
            best = (objective, row)
    if best is None:
        raise RuntimeError("No five-stage bounded subtype combination meets the support gate")
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
    selected, pools = choose_bounded(sequences, table)

    reserve_pairs = {(stage, subtype) for stage, subtype in selected["chosen"].items()}
    output = {
        "protocol": "V76b bounded support-only X-IIoTID Class3 unseen-subtype freeze",
        "supersedes": "V76 exhaustive support search only for runtime efficiency; no V76 model metric existed",
        "dataset_sha256": sha256(csv),
        "selection_used_model_metrics": False,
        "model_scored_reserve_before_freeze": False,
        "combination_search_bound": int(MAX_CANDIDATES_PER_STAGE ** len(STAGES)),
        "binary_label_column": binary_col,
        "lifecycle_family_column": family_col,
        "fine_subtype_column": subtype_col,
        "source_column": src_col,
        "selected_reserve_subtype_by_stage": selected["chosen"],
        "reserve_stage_support": selected["reserve_support"],
        "development_stage_support_after_all_reserves": selected["development_support"],
        "total_stage_support": total_stage_support,
        "minimum_reserve_per_stage": MIN_RESERVE_PER_STAGE,
        "minimum_development_per_stage": MIN_DEV_PER_STAGE,
        "reserve_touch_sequence_count": int(sum(bool(reserve_pairs.intersection(r["all_pairs"])) for r in sequences)),
        "sequence_count": int(len(sequences)),
        "candidate_pools": pools,
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method},
        "label_profiles": profiles,
        "stage_mapping": {
            "Reconnaissance": "Reconnaissance",
            "Exploitation": "Initial Access proxy",
            "Lateral Movement": "Lateral Movement",
            "C&C": "Command & Control",
            "Exfiltration": "Exfiltration",
        },
        "target_rule": "furthest mapped lifecycle stage in next four one-minute windows; unique Class3 subtype required for that target stage",
        "test_support_rule": "selected target subtype appears in future, not history; no other selected reserve subtype may touch the 12-window sequence",
        "claim_boundary": "Support-only freeze. No selected reserve subtype has been model-scored. Exploitation is an Initial Access proxy, not exact MITRE truth.",
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "dataset_sha256": output["dataset_sha256"],
        "selected_reserve_subtype_by_stage": output["selected_reserve_subtype_by_stage"],
        "reserve_stage_support": output["reserve_stage_support"],
        "development_stage_support_after_all_reserves": output["development_stage_support_after_all_reserves"],
        "total_stage_support": output["total_stage_support"],
        "sequence_count": output["sequence_count"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
