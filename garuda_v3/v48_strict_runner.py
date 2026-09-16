"""Strict V48 orchestration with reserve-family isolation before score development.

The reserve family set is chosen using support counts only. Every sequence touching a
reserve family (plus an overlap embargo) is excluded from V48 score-development
training, calibration, policy fitting *and fusion-selection evaluation*. Only after the
fusion rule is frozen and hashed are reserve-family metrics evaluated.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import (
    HISTORY,
    HORIZON,
    FPR_BUDGET,
    SEEDS,
    norm,
    sha256,
    parse_time,
    detect_label_hierarchy,
    choose_network_numeric_features,
    build_minute_state,
    make_sequences,
    temporal_masks,
    train_world_model,
)
from .v47_leave_one_family import leave_one_family_split
from .v48_unseen_fusion import (
    COMPONENTS,
    EXPOSED_DEVELOPMENT_FAMILIES,
    raw_components,
    choose_fusion,
    family_support,
    evaluate_reserve_family,
    _canonical_hash,
)

EMBARGO_STEPS = HISTORY + HORIZON


def reserve_exposure_mask(sequences, reserve_families):
    """Mask sequences touching reserve-family raw windows plus overlap neighbors."""
    reserve = set(reserve_families)
    if not reserve:
        return np.zeros(len(sequences["X"]), dtype=bool)

    touched = np.zeros(len(sequences["X"]), dtype=bool)
    for i, (history, steps) in enumerate(zip(sequences["history_families"], sequences["step_families"])):
        if reserve.intersection(history):
            touched[i] = True
            continue
        if any(reserve.intersection(step) for step in steps):
            touched[i] = True

    cutoff = sequences["cutoff"]
    touched_times = cutoff[touched]
    blocked_times = set()
    for t in touched_times.tolist():
        for k in range(-EMBARGO_STEPS, EMBARGO_STEPS + 1):
            blocked_times.add(int(t + 60 * k))
    overlap = np.asarray([int(t) in blocked_times for t in cutoff], dtype=bool)
    return touched | overlap


def apply_reserve_isolation(split, reserve_mask):
    """Remove reserve evidence from fitting and from fusion-selection scoring."""
    out = dict(split)
    for name in ("train", "calibration", "policy"):
        out[name] = out[name] & ~reserve_mask

    # Exposed-family development metrics must not be influenced by a co-occurring
    # reserve family or by overlapping raw windows. Benign negatives near reserve
    # episodes are also removed so score selection never sees reserve-adjacent traffic.
    out["test_positive"] = out["test_positive"] & ~reserve_mask
    out["test_negative"] = out["test_negative"] & ~reserve_mask
    out["test_eval"] = out["test_positive"] | out["test_negative"]
    if "clean_onset_positive" in out:
        out["clean_onset_positive"] = out["clean_onset_positive"] & ~reserve_mask
    return out


def prepare_isolated_development_fold(sequences, time_masks, family, seed, epochs, reserve_mask):
    split = apply_reserve_isolation(
        leave_one_family_split(sequences, time_masks, family), reserve_mask
    )
    world = train_world_model(
        sequences["X"], sequences["future"], split["train"], split["calibration"], seed, epochs=epochs
    )
    components = raw_components(world, sequences, split, seed)
    if components is None:
        return None
    if int(split["test_positive"].sum()) == 0 or int(split["test_negative"].sum()) == 0:
        return None
    return {"family": family, "seed": seed, "split": split, "world": world, "components": components}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=12)
    p.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    p.add_argument("--min-positive", type=int, default=20)
    p.add_argument("--min-negative", type=int, default=50)
    p.add_argument("--max-reserve-families", type=int, default=4)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V48 evidence is immutable")
    out.mkdir(parents=True)

    csv_path = Path(args.csv)
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, label_profiles = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    sequences = make_sequences(state, state_features)
    time_masks, boundaries = temporal_masks(sequences["cutoff"])

    all_families = sorted({item for steps in sequences["step_families"] for fams in steps for item in fams})
    support = [family_support(sequences, time_masks, fam) for fam in all_families]
    exposed = [fam for fam in EXPOSED_DEVELOPMENT_FAMILIES if fam in all_families]
    if len(exposed) < 3:
        raise RuntimeError(f"Expected at least three exposed V47 development families, found {exposed}")

    reserve_candidates = [
        r for r in support
        if r["family"] not in set(exposed)
        and r["positive"] >= args.min_positive
        and r["negative"] >= args.min_negative
        and r["train"] >= 50
        and r["calibration"] >= 20
        and r["policy"] >= 20
    ]
    reserve_candidates.sort(key=lambda r: (-r["positive"], r["family"]))
    reserve = [r["family"] for r in reserve_candidates[:args.max_reserve_families]]
    reserve_mask = reserve_exposure_mask(sequences, reserve)

    dev_cache = []
    dev_support = {r["family"]: r for r in support}
    for fam in exposed:
        s = dev_support[fam]
        if s["positive"] < args.min_positive or s["negative"] < args.min_negative:
            continue
        for seed in args.seeds:
            print(f"V48 isolated-development family={fam} seed={seed} reserve={reserve}", flush=True)
            fold = prepare_isolated_development_fold(
                sequences, time_masks, fam, seed, args.epochs, reserve_mask
            )
            if fold is not None:
                dev_cache.append(fold)
    if len(dev_cache) < 3:
        raise RuntimeError("Insufficient reserve-isolated development folds for fusion selection")

    winner, candidate_table = choose_fusion(dev_cache)
    frozen = {
        "protocol": "V48 strict frozen unseen-family alert fusion",
        "development_families": exposed,
        "reserve_families": reserve,
        "reserve_selection_method": "support only before score development",
        "reserve_sequences_excluded_from_model_fitting": True,
        "reserve_sequences_excluded_from_fusion_selection_metrics": True,
        "reserve_overlap_embargo_steps_each_side": EMBARGO_STEPS,
        "reserve_blocked_sequence_count": int(reserve_mask.sum()),
        "components": list(COMPONENTS),
        "weights": winner["weights"],
        "policy_budget": winner["policy_budget"],
        "selection_objective": winner["objective"],
        "selection_candidate": winner["name"],
        "selection_rule": "lexicographic: gate folds, safe recall sum, safe folds, safe mean recall, lower max FPR, lower policy budget",
        "reserve_metrics_used_for_selection": False,
    }
    frozen["config_sha256"] = _canonical_hash(frozen)
    (out / "frozen_score_config.json").write_text(json.dumps(frozen, indent=2, allow_nan=False) + "\n")

    report = {
        "protocol": "V48 strict frozen unseen-family alert fusion",
        "claim_boundary": "Reserve public-dataset families have no V48 model, calibration, policy or score-selection exposure. This is still not proof of a real undisclosed zero-day or verified compromise lead time.",
        "source": {
            "filename": csv_path.name,
            "bytes": int(csv_path.stat().st_size),
            "sha256": sha256(csv_path),
            "rows": int(len(df)),
            "columns": int(len(df.columns)),
        },
        "history_minutes": HISTORY,
        "horizon_minutes": HORIZON,
        "seeds": list(args.seeds),
        "release_gate": {"fpr_max": FPR_BUDGET, "recall_min": 0.80},
        "network_only_feature_audit": {"raw_selected": feature_cols, "state_feature_count": len(state_features), "audit": feature_audit},
        "label_columns": {"binary": binary_col, "family": family_col, "profiles": label_profiles},
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method, "boundaries": boundaries},
        "state_rows": int(len(state)),
        "sequence_rows": int(len(sequences["X"])),
        "source_group_column": src_col,
        "family_support": support,
        "development": {
            "families": exposed,
            "reserve_blocked_sequence_count": int(reserve_mask.sum()),
            "folds": len(dev_cache),
            "winner": winner,
            "candidate_count": len(candidate_table),
        },
        "frozen_score_config": frozen,
        "reserve_selection": {
            "method": "largest support-qualified non-V47 families, frozen before score development",
            "selected": reserve,
            "eligible": reserve_candidates,
        },
        "reserve_results": {},
        "automatic_containment_approved": False,
    }

    for fam in reserve:
        print(f"V48 STRICT RESERVE family={fam} config_sha256={frozen['config_sha256']}", flush=True)
        result = evaluate_reserve_family(
            sequences, time_masks, fam, tuple(args.seeds), args.epochs, frozen
        )
        report["reserve_results"][fam] = result
        (out / f"reserve_{norm(fam)}.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")

    report["all_reserve_unseen_gates_passed"] = bool(
        reserve and all(v["summary"]["unseen_gate_passed_all_seeds"] for v in report["reserve_results"].values())
    )
    report["pre_compromise_claim_supported"] = False
    report["reason_pre_compromise_unavailable"] = "Dataset family labels do not independently establish successful compromise timestamps/lead time."
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")

    print(json.dumps({
        "frozen_score_config": frozen,
        "reserve_families": reserve,
        "reserve_summaries": {k: v["summary"] for k, v in report["reserve_results"].items()},
        "all_reserve_unseen_gates_passed": report["all_reserve_unseen_gates_passed"],
    }, indent=2, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
