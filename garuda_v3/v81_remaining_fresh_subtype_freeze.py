"""V81 support-only audit for a third untouched X-IIoTID fine-subtype reserve.

V78b and V80 have already scored four Class1 fine subtypes.  They are now permanently
ineligible as "fresh" evidence.  This script performs NO model training or scoring.  It
checks whether any additional subtype-disjoint stage holdout still satisfies the same
support gates.  Exhaustion is a valid result and is written as evidence instead of being
forced into a fake benchmark.
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
from .v76f_supported_stage_subtype_freeze import _candidate_pools, choose_maximal

EXPOSED = {
    "Reconnaissance": {"discovering resources", "fuzzing"},
    "Lateral Movement": {"modbus register reading", "mqtt cloud broker subscription"},
}


def remove_exposed_candidates(table):
    filtered, removed = {}, {}
    for stage in STAGES:
        blocked = EXPOSED.get(stage, set())
        filtered[stage] = [r for r in table[stage] if r["subtype"] not in blocked]
        removed[stage] = [r for r in table[stage] if r["subtype"] in blocked]
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

    selection_error = None
    try:
        selected, search_audit = choose_maximal(sequences, pools)
    except RuntimeError as exc:
        selection_error = str(exc)
        selected = {
            "chosen": {},
            "reserve_support": {},
            "clean_onset_support_diagnostic_only": {},
            "development_support_all_stages": {},
            "qualified": False,
        }
        search_audit = {"subsets_considered": 0, "candidate_combinations_considered": 0}

    selected_stages = [stage for stage in STAGES if stage in selected["chosen"]]
    for stage, subtype in selected["chosen"].items():
        if subtype in EXPOSED.get(stage, set()):
            raise RuntimeError(f"Previously scored subtype re-entered reserve: {stage}/{subtype}")

    eligible_remaining = {
        stage: [row["subtype"] for row in pools[stage]]
        for stage in STAGES
    }
    fresh_exhausted = len(selected_stages) == 0
    reserve_pairs = {(stage, subtype) for stage, subtype in selected["chosen"].items()}

    output = {
        "protocol": "V81 third-reserve support-only X-IIoTID Class1 subtype freshness audit",
        "selection_used_model_metrics": False,
        "model_training_or_scoring_performed": False,
        "model_scored_reserve_before_freeze": False,
        "all_previously_scored_subtypes_excluded": True,
        "previously_scored_subtypes_by_stage": {k: sorted(v) for k, v in EXPOSED.items()},
        "dataset_sha256": sha256(csv),
        "binary_label_column": binary_col,
        "lifecycle_family_column": family_col,
        "fine_subtype_column": subtype_col,
        "source_column": src_col,
        "fresh_holdout_exhausted_under_declared_support_gates": fresh_exhausted,
        "selection_error_if_exhausted": selection_error,
        "selected_stage_count": int(len(selected_stages)),
        "selected_stages": selected_stages,
        "selected_reserve_subtype_by_stage": selected["chosen"],
        "reserve_stage_support": selected["reserve_support"],
        "clean_onset_support_diagnostic_only": selected["clean_onset_support_diagnostic_only"],
        "development_stage_support_after_all_reserves": selected["development_support_all_stages"],
        "eligible_remaining_candidate_subtypes_by_stage": eligible_remaining,
        "individual_stage_supportability_after_all_exposed_exclusion": individual_status,
        "candidate_support_after_all_exposed_exclusion": table,
        "removed_previously_scored_candidate_rows": removed,
        "total_stage_support": total_stage_support,
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
        "claim_boundary": (
            "This is a support-only freshness audit. It excludes every fine subtype already scored in V78b and V80. "
            "If no qualifying holdout remains, X-IIoTID is declared exhausted for another fresh subtype test under the current support gates; no score is fabricated."
        ),
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "dataset_sha256": output["dataset_sha256"],
        "excluded_exposed": output["previously_scored_subtypes_by_stage"],
        "fresh_holdout_exhausted": fresh_exhausted,
        "selected_stage_count": output["selected_stage_count"],
        "selected": output["selected_reserve_subtype_by_stage"],
        "reserve_support": output["reserve_stage_support"],
        "eligible_remaining": eligible_remaining,
        "individual_stage_supportability": individual_status,
        "selection_error": selection_error,
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
