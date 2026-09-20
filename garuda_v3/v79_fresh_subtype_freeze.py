"""V79 fresh support-only fine-subtype freeze after the exposed V78 diagnostic.

V78b has already scored two Class1 subtypes:
  Reconnaissance -> discovering resources
  Lateral Movement -> modbus register reading
Those pairs are development evidence now and are permanently ineligible for V79 reserve
selection. V79 performs NO model training or scoring. It selects the largest supportable
set of *different* Class1 subtype holdouts using only target/development support counts.
The resulting freeze is intended for a later V80 test after architecture work.
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
    build_minute_pairs,
    candidate_table,
    make_sequence_metadata,
    sha256,
)
from .v76f_supported_stage_subtype_freeze import (
    _candidate_pools,
    choose_maximal,
)

EXPOSED_V78 = {
    "Reconnaissance": "discovering resources",
    "Lateral Movement": "modbus register reading",
}


def remove_exposed_candidates(table):
    filtered = {}
    removed = {}
    for stage in STAGES:
        blocked = EXPOSED_V78.get(stage)
        filtered[stage] = [row for row in table[stage] if row["subtype"] != blocked]
        removed[stage] = [row for row in table[stage] if row["subtype"] == blocked]
    return filtered, removed


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    csv = Path(args.csv)
    df = pd.read_csv(csv, low_memory=False)
    columns = {norm(c): c for c in df.columns}
    if not {"class1", "class2", "class3"}.issubset(columns):
        raise RuntimeError("Audited class1/class2/class3 hierarchy is missing")

    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    if norm(binary_col) != "class3" or norm(family_col) != "class2":
        raise RuntimeError(
            f"Hierarchy drift: expected class3 binary/class2 family, got {binary_col}/{family_col}"
        )
    subtype_col = columns["class1"]
    family = family.map(canonical_family_name)

    minute_pairs, src_col = build_minute_pairs(df, dt, binary, family, subtype_col)
    sequences = make_sequence_metadata(minute_pairs)
    full_table, total_stage_support = candidate_table(sequences)
    table, removed = remove_exposed_candidates(full_table)
    pools, individual_status = _candidate_pools(table)
    selected, search_audit = choose_maximal(sequences, pools)

    selected_stages = [stage for stage in STAGES if stage in selected["chosen"]]
    if any(selected["chosen"].get(stage) == subtype for stage, subtype in EXPOSED_V78.items()):
        raise RuntimeError("Previously scored V78 subtype re-entered V79 reserve")

    unsupported = {}
    for stage in STAGES:
        if stage in selected["chosen"]:
            continue
        status = individual_status[stage]
        if not status["supportable_individually"]:
            unsupported[stage] = status
        else:
            unsupported[stage] = {
                "supportable_individually": True,
                "reason": "not_in_maximal_combined_freeze_due_to_cross_reserve_support_constraints",
                "top_candidates": status["top_candidates"],
            }

    reserve_pairs = {(stage, subtype) for stage, subtype in selected["chosen"].items()}
    output = {
        "protocol": "V79 fresh post-V78 support-only X-IIoTID Class1 subtype freeze",
        "selection_used_model_metrics": False,
        "model_scored_reserve_before_freeze": False,
        "previously_scored_subtypes_excluded_from_selection": True,
        "previously_scored_v78_subtype_by_stage": EXPOSED_V78,
        "dataset_sha256": sha256(csv),
        "binary_label_column": binary_col,
        "lifecycle_family_column": family_col,
        "fine_subtype_column": subtype_col,
        "source_column": src_col,
        "selected_stage_count": int(len(selected_stages)),
        "selected_stages": selected_stages,
        "selected_reserve_subtype_by_stage": selected["chosen"],
        "reserve_stage_support": selected["reserve_support"],
        "clean_onset_support_diagnostic_only": selected["clean_onset_support_diagnostic_only"],
        "development_stage_support_after_all_reserves": selected["development_support_all_stages"],
        "unsupported_stage_audit": unsupported,
        "individual_stage_supportability_after_exposed_exclusion": individual_status,
        "total_stage_support": total_stage_support,
        "candidate_support_after_exposed_exclusion": table,
        "removed_exposed_candidate_rows": removed,
        "sequence_count": int(len(sequences)),
        "reserve_touch_sequence_count": int(sum(
            bool(reserve_pairs.intersection(row["all_pairs"])) for row in sequences
        )),
        "search_audit": search_audit,
        "time": {
            "date_column": date_col,
            "timestamp_column": ts_col,
            "method": time_method,
        },
        "label_profiles": profiles,
        "stage_mapping": {
            "Reconnaissance": "Reconnaissance",
            "Exploitation": "Initial Access proxy",
            "Lateral Movement": "Lateral Movement",
            "C&C": "Command & Control",
            "Exfiltration": "Exfiltration",
        },
        "claim_boundary": (
            "Fresh reserve selection is support-only and excludes every Class1 subtype already scored in V78b. "
            "No V79 reserve model score exists at freeze time. Clean-onset support is diagnostic only, and Exploitation remains an Initial Access proxy."
        ),
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "dataset_sha256": output["dataset_sha256"],
        "excluded_exposed": EXPOSED_V78,
        "selected_stage_count": output["selected_stage_count"],
        "selected_stages": output["selected_stages"],
        "selected_reserve_subtype_by_stage": output["selected_reserve_subtype_by_stage"],
        "reserve_stage_support": output["reserve_stage_support"],
        "clean_onset_support_diagnostic_only": output["clean_onset_support_diagnostic_only"],
        "development_stage_support_after_all_reserves": output["development_stage_support_after_all_reserves"],
        "unsupported_stage_audit": output["unsupported_stage_audit"],
        "search_audit": output["search_audit"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
