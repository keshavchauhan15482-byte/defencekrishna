"""V76d support-only fine-subtype freeze for stage generalisation.

This is deliberately NOT a pre-onset benchmark. X-IIoTID reconnaissance subtypes have
zero clean-onset sequence support under Garuda's 8-minute history / 4-minute horizon,
so requiring a subtype to be absent from history would make a five-stage benchmark
impossible. V76d freezes one Class1 fine subtype per lifecycle stage using only future
target support and remaining reserve-free development support. No model is trained or
scored in this step.

The selected subtype is still completely excluded from V77b model/mapper development.
At evaluation time it may already be visible in the observed history; therefore the
claim is unseen-subtype future-state/stage generalisation, not pre-compromise warning.
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


def choose_generalization_combination(rows, table):
    pools = {}
    for stage in STAGES:
        eligible = [
            row for row in table[stage]
            if row["target_support"] >= MIN_RESERVE_PER_STAGE
            and row["remaining_stage_support_if_held_out_alone"][stage] >= MIN_DEV_PER_STAGE
        ][:MAX_CANDIDATES_PER_STAGE]
        if not eligible:
            raise RuntimeError(
                f"No support-qualified fine subtype for {stage}; candidates={table[stage][:12]}"
            )
        pools[stage] = eligible

    best = None
    audits = []
    for combo in itertools.product(*(pools[stage] for stage in STAGES)):
        chosen = {stage: row["subtype"] for stage, row in zip(STAGES, combo)}
        reserve_pairs = {(stage, subtype) for stage, subtype in chosen.items()}
        reserve_support = {}
        clean_onset_support = {}
        dev_support = {}
        history_exposed_support = {}
        for stage in STAGES:
            subtype = chosen[stage]
            pair = (stage, subtype)
            target_rows = [
                r for r in rows
                if r["target_stage"] == stage and subtype in r["target_subtypes"]
            ]
            reserve_support[stage] = int(len(target_rows))
            clean_onset_support[stage] = int(sum(pair not in r["history_pairs"] for r in target_rows))
            history_exposed_support[stage] = int(sum(pair in r["history_pairs"] for r in target_rows))
            dev_support[stage] = int(sum(
                1 for r in rows
                if r["target_stage"] == stage
                and r["target_subtypes"]
                and not reserve_pairs.intersection(r["all_pairs"])
            ))

        ok = (
            all(v >= MIN_RESERVE_PER_STAGE for v in reserve_support.values())
            and all(v >= MIN_DEV_PER_STAGE for v in dev_support.values())
        )
        row = {
            "chosen": chosen,
            "reserve_support": reserve_support,
            "clean_onset_support_diagnostic": clean_onset_support,
            "history_exposed_support_diagnostic": history_exposed_support,
            "development_support": dev_support,
            "qualified": bool(ok),
        }
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
        best_rows = sorted(
            audits,
            key=lambda r: (
                min(r["reserve_support"].values()),
                min(r["development_support"].values()),
            ),
            reverse=True,
        )[:10]
        raise RuntimeError(f"No five-stage subtype combination meets support gate; best={best_rows}")
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
    selected, pools = choose_generalization_combination(sequences, table)

    reserve_pairs = {(stage, subtype) for stage, subtype in selected["chosen"].items()}
    reserve_touch_count = sum(bool(reserve_pairs.intersection(r["all_pairs"])) for r in sequences)
    output = {
        "protocol": "V76d support-only X-IIoTID fine-subtype generalization freeze",
        "dataset_sha256": sha256(csv),
        "selection_used_model_metrics": False,
        "model_scored_reserve_before_freeze": False,
        "selection_uses_clean_onset_support": False,
        "binary_label_column": binary_col,
        "lifecycle_family_column": family_col,
        "fine_subtype_column": subtype_col,
        "verified_label_hierarchy": {
            "binary": binary_col,
            "lifecycle": family_col,
            "fine_subtype": subtype_col,
        },
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
        "reserve_clean_onset_support_diagnostic": selected["clean_onset_support_diagnostic"],
        "reserve_history_exposed_support_diagnostic": selected["history_exposed_support_diagnostic"],
        "development_stage_support_after_all_reserves": selected["development_support"],
        "total_stage_support": total_stage_support,
        "reserve_touch_sequence_count": int(reserve_touch_count),
        "sequence_count": int(len(sequences)),
        "support_candidate_pools": {stage: pools[stage] for stage in STAGES},
        "all_candidate_support": table,
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method},
        "label_profiles": profiles,
        "target_rule": "furthest mapped lifecycle stage in next four one-minute windows; all fine subtypes at that target stage retained",
        "claim_boundary": (
            "Support-only freeze. Selected Class1 fine subtypes have no model/mapper exposure during development. "
            "Evaluation histories may already contain the held-out subtype, so this supports unseen-subtype future-stage generalisation only; it is not a clean-onset, pre-compromise, or zero-day proof. Exploitation remains an Initial Access proxy."
        ),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "dataset_sha256": output["dataset_sha256"],
        "verified_label_hierarchy": output["verified_label_hierarchy"],
        "selected_reserve_subtype_by_stage": selected["chosen"],
        "reserve_stage_support": selected["reserve_support"],
        "clean_onset_support_diagnostic": selected["clean_onset_support_diagnostic"],
        "history_exposed_support_diagnostic": selected["history_exposed_support_diagnostic"],
        "development_stage_support_after_all_reserves": selected["development_support"],
        "sequence_count": len(sequences),
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
