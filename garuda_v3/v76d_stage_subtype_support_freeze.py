"""V76d audited X-IIoTID fine-subtype support freeze.

V76c established the actual dataset hierarchy: class3 is binary Attack/Normal,
class2 is the lifecycle family, and class1 is the fine attack subtype. This script
therefore freezes one unseen class1 subtype per supported lifecycle stage using support
counts only. No model is trained or scored.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .v47_unseen_family import detect_label_hierarchy, norm, parse_time
from .v48_strict_runner import canonical_family_name
from .v71_future_stage_proxy import STAGES
from .v76_stage_subtype_support_freeze import (
    MIN_DEV_PER_STAGE,
    MIN_RESERVE_PER_STAGE,
    build_minute_pairs,
    candidate_table,
    make_sequence_metadata,
    sha256,
)
from .v76b_stage_subtype_support_freeze import MAX_CANDIDATES_PER_STAGE, choose_bounded


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    csv = Path(args.csv)
    df = pd.read_csv(csv, low_memory=False)
    columns = {norm(c): c for c in df.columns}
    required = {"class1", "class2", "class3"}
    if not required.issubset(columns):
        raise RuntimeError(f"Missing audited hierarchy columns: {required - set(columns)}")

    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    subtype_col = columns["class1"]
    if norm(binary_col) != "class3" or norm(family_col) != "class2":
        raise RuntimeError(f"Hierarchy drift: expected class3 binary/class2 family, got {binary_col}/{family_col}")
    family = family.map(canonical_family_name)

    minute_pairs, src_col = build_minute_pairs(df, dt, binary, family, subtype_col)
    sequences = make_sequence_metadata(minute_pairs)
    table, total_stage_support = candidate_table(sequences)
    selected, pools = choose_bounded(sequences, table)
    reserve_pairs = {(stage, subtype) for stage, subtype in selected["chosen"].items()}

    output = {
        "protocol": "V76d audited support-only X-IIoTID class1 unseen-subtype freeze",
        "schema_audit_run": 35527685335,
        "supersedes": [
            "V76/V76b assumed class3 was fine subtype before raw hierarchy audit; no model reserve metric was produced",
            "V75 source-host holdout lacked five-stage support",
        ],
        "dataset_sha256": sha256(csv),
        "selection_used_model_metrics": False,
        "model_scored_reserve_before_freeze": False,
        "binary_label_column": binary_col,
        "lifecycle_family_column": family_col,
        "fine_subtype_column": subtype_col,
        "source_column": src_col,
        "hierarchy_contract": {
            "class3": "binary Attack/Normal",
            "class2": "coarse lifecycle/attack family",
            "class1": "fine attack subtype",
        },
        "selected_reserve_subtype_by_stage": selected["chosen"],
        "reserve_stage_support": selected["reserve_support"],
        "development_stage_support_after_all_reserves": selected["development_support"],
        "total_stage_support": total_stage_support,
        "minimum_reserve_per_stage": MIN_RESERVE_PER_STAGE,
        "minimum_development_per_stage": MIN_DEV_PER_STAGE,
        "max_candidates_per_stage": MAX_CANDIDATES_PER_STAGE,
        "combination_search_bound": int(MAX_CANDIDATES_PER_STAGE ** len(STAGES)),
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
        "target_rule": "furthest mapped class2 lifecycle stage in next four one-minute windows; unique class1 subtype required in that target stage",
        "test_support_rule": "selected target subtype occurs in future, not history; no other selected reserve subtype touches the 12-window sequence",
        "claim_boundary": "Support-only freeze. No selected class1 reserve subtype has been model-scored. Exploitation maps only to an Initial Access proxy.",
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "dataset_sha256": output["dataset_sha256"],
        "hierarchy_contract": output["hierarchy_contract"],
        "selected_reserve_subtype_by_stage": output["selected_reserve_subtype_by_stage"],
        "reserve_stage_support": output["reserve_stage_support"],
        "development_stage_support_after_all_reserves": output["development_stage_support_after_all_reserves"],
        "total_stage_support": output["total_stage_support"],
        "sequence_count": output["sequence_count"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
