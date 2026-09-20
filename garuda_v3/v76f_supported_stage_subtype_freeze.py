"""V76f maximal supportable unseen-subtype stage freeze.

Support-only protocol for X-IIoTID after the V76c hierarchy audit established:
  class3 = binary Attack/Normal
  class2 = lifecycle/coarse family
  class1 = fine attack subtype

A five-stage subtype-disjoint benchmark is not assumed.  This script finds the largest
subset of lifecycle stages for which one class1 subtype can be held out with sufficient
reserve support while leaving sufficient development support after *all* selected
reserve subtypes are isolated.  Selection uses support counts only; no model is trained
or scored here.
"""
from __future__ import annotations

import argparse
import itertools
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

MAX_CANDIDATES_PER_STAGE = 4


def _candidate_pools(table):
    pools = {}
    individual_status = {}
    for stage in STAGES:
        raw = table[stage]
        eligible = [
            row for row in raw
            if row["target_support"] >= MIN_RESERVE_PER_STAGE
            and row["remaining_stage_support_if_held_out_alone"][stage] >= MIN_DEV_PER_STAGE
        ]
        eligible.sort(key=lambda row: (-row["target_support"], -row["remaining_stage_support_if_held_out_alone"][stage], row["subtype"]))
        pools[stage] = eligible[:MAX_CANDIDATES_PER_STAGE]
        if eligible:
            individual_status[stage] = {
                "supportable_individually": True,
                "eligible_candidate_count": int(len(eligible)),
                "top_candidates": eligible[:MAX_CANDIDATES_PER_STAGE],
            }
        else:
            reason = "no_fine_subtype_with_required_reserve_and_remaining_development_support"
            if raw and all(row["remaining_stage_support_if_held_out_alone"][stage] < MIN_DEV_PER_STAGE for row in raw):
                reason = "holding_out_any_fine_subtype_leaves_insufficient_same_stage_development_support"
            elif raw and all(row["target_support"] < MIN_RESERVE_PER_STAGE for row in raw):
                reason = "all_fine_subtypes_have_insufficient_reserve_target_support"
            elif not raw:
                reason = "no_unique_fine_subtype_targets_in_sequence_contract"
            individual_status[stage] = {
                "supportable_individually": False,
                "reason": reason,
                "all_candidates": raw[:20],
            }
    return pools, individual_status


def _score_combination(rows, chosen):
    reserve_pairs = {(stage, subtype) for stage, subtype in chosen.items()}
    reserve_support = {}
    development_support = {}
    clean_onset_support = {}

    for stage, subtype in chosen.items():
        pair = (stage, subtype)
        reserve_support[stage] = int(sum(
            1 for row in rows
            if row["target_stage"] == stage
            and row["target_subtype"] == subtype
            and pair in row["future_pairs"]
            and not (reserve_pairs - {pair}).intersection(row["all_pairs"])
        ))
        clean_onset_support[stage] = int(sum(
            1 for row in rows
            if row["target_stage"] == stage
            and row["target_subtype"] == subtype
            and pair in row["future_pairs"]
            and pair not in row["history_pairs"]
            and not (reserve_pairs - {pair}).intersection(row["all_pairs"])
        ))

    # Development support is audited for every mapped stage, not only held-out stages.
    for stage in STAGES:
        development_support[stage] = int(sum(
            1 for row in rows
            if row["target_stage"] == stage
            and row["target_subtype"] is not None
            and not reserve_pairs.intersection(row["all_pairs"])
        ))

    valid = (
        all(v >= MIN_RESERVE_PER_STAGE for v in reserve_support.values())
        and all(development_support[s] >= MIN_DEV_PER_STAGE for s in chosen)
    )
    return {
        "chosen": dict(chosen),
        "reserve_support": reserve_support,
        "clean_onset_support_diagnostic_only": clean_onset_support,
        "development_support_all_stages": development_support,
        "qualified": bool(valid),
    }


def choose_maximal(rows, pools):
    individually = [stage for stage in STAGES if pools[stage]]
    if not individually:
        raise RuntimeError("No lifecycle stage supports a subtype-disjoint reserve under the declared support gates")

    best = None
    best_row = None
    audit_counts = {"subsets_considered": 0, "candidate_combinations_considered": 0}

    # Largest stage subset first.  Within a fixed cardinality, choose by support only.
    for size in range(len(individually), 0, -1):
        found_at_size = []
        for subset in itertools.combinations(individually, size):
            audit_counts["subsets_considered"] += 1
            candidate_lists = [pools[stage] for stage in subset]
            for combo in itertools.product(*candidate_lists):
                audit_counts["candidate_combinations_considered"] += 1
                chosen = {stage: row["subtype"] for stage, row in zip(subset, combo)}
                scored = _score_combination(rows, chosen)
                if not scored["qualified"]:
                    continue
                reserve_vals = list(scored["reserve_support"].values())
                selected_dev = [scored["development_support_all_stages"][s] for s in subset]
                objective = (
                    len(subset),
                    min(reserve_vals),
                    min(selected_dev),
                    sum(reserve_vals),
                    sum(selected_dev),
                    tuple((stage, chosen[stage]) for stage in subset),
                )
                found_at_size.append((objective, scored))
        if found_at_size:
            best, best_row = max(found_at_size, key=lambda item: item[0])
            break

    if best_row is None:
        raise RuntimeError("No combined subtype reserve satisfies declared support gates")
    return best_row, audit_counts


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
        raise RuntimeError(f"Hierarchy drift: expected class3 binary/class2 family, got {binary_col}/{family_col}")
    subtype_col = columns["class1"]
    family = family.map(canonical_family_name)

    minute_pairs, src_col = build_minute_pairs(df, dt, binary, family, subtype_col)
    sequences = make_sequence_metadata(minute_pairs)
    table, total_stage_support = candidate_table(sequences)
    pools, individual_status = _candidate_pools(table)
    selected, search_audit = choose_maximal(sequences, pools)

    selected_stages = [stage for stage in STAGES if stage in selected["chosen"]]
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
        "protocol": "V76f maximal support-only X-IIoTID class1 unseen-subtype stage freeze",
        "schema_audit_run": 35527685335,
        "selection_used_model_metrics": False,
        "model_scored_reserve_before_freeze": False,
        "dataset_sha256": sha256(csv),
        "binary_label_column": binary_col,
        "lifecycle_family_column": family_col,
        "fine_subtype_column": subtype_col,
        "source_column": src_col,
        "support_gates": {
            "minimum_reserve_target_sequences_per_selected_stage": MIN_RESERVE_PER_STAGE,
            "minimum_remaining_development_sequences_per_selected_stage": MIN_DEV_PER_STAGE,
            "max_candidates_per_stage_in_combination_search": MAX_CANDIDATES_PER_STAGE,
        },
        "selected_stage_count": int(len(selected_stages)),
        "selected_stages": selected_stages,
        "selected_reserve_subtype_by_stage": selected["chosen"],
        "reserve_stage_support": selected["reserve_support"],
        "clean_onset_support_diagnostic_only": selected["clean_onset_support_diagnostic_only"],
        "development_stage_support_after_all_reserves": selected["development_support_all_stages"],
        "unsupported_stage_audit": unsupported,
        "individual_stage_supportability": individual_status,
        "total_stage_support": total_stage_support,
        "all_candidate_support": table,
        "sequence_count": int(len(sequences)),
        "reserve_touch_sequence_count": int(sum(bool(reserve_pairs.intersection(row["all_pairs"])) for row in sequences)),
        "search_audit": search_audit,
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method},
        "label_profiles": profiles,
        "stage_mapping": {
            "Reconnaissance": "Reconnaissance",
            "Exploitation": "Initial Access proxy",
            "Lateral Movement": "Lateral Movement",
            "C&C": "Command & Control",
            "Exfiltration": "Exfiltration",
        },
        "evaluation_scope": "zero-development-exposure fine-subtype generalisation only on selected supported stages; not a five-stage claim unless selected_stage_count equals five",
        "development_isolation_rule": "V77 must exclude every sequence touching any selected (stage,class1 subtype) pair, plus overlap-neighbour embargo, from world-model and stage-mapper development",
        "claim_boundary": "Clean-onset support is diagnostic only. A reserve subtype can already appear in a test sequence history. This is not pre-attack onset evidence and Exploitation remains only an Initial Access proxy.",
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "dataset_sha256": output["dataset_sha256"],
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
